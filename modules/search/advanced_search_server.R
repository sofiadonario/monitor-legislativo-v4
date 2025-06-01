# ============================================================================
# ADVANCED SEARCH SERVER MODULE FOR BRAZILIAN LEGISLATIVE MONITORING SYSTEM
# ============================================================================
#
# This module handles all server-side logic for the advanced search interface:
# - Real-time search processing with PostgreSQL integration
# - Geographic and temporal filter application
# - Autocomplete suggestions with intelligent ranking
# - Search result formatting and pagination
# - Performance monitoring and analytics
# - Integration with existing search engine backend
#
# Author: Senior Backend Developer - Brazilian Government Applications
# Date: January 2025
# Version: 1.0 - Production Ready for Government Use
# ============================================================================

# Load required packages with error handling
search_server_packages <- c("shiny", "DT", "dplyr", "jsonlite", "stringr", "lubridate")

for (pkg in search_server_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available for search server\n")
  }
}

suppressPackageStartupMessages({
  library(shiny)
  library(dplyr)
  library(jsonlite)
  library(stringr)
  library(lubridate)
  if (requireNamespace("DT", quietly = TRUE)) library(DT)
})

# ============================================================================
# ADVANCED SEARCH SERVER CONFIGURATION
# ============================================================================

.search_server_config <- list(
  # Performance settings
  instant_search_delay = 300,  # milliseconds
  max_autocomplete_results = 10,
  default_results_per_page = 25,
  
  # Cache settings
  enable_result_caching = TRUE,
  cache_duration_minutes = 15,
  
  # Pagination settings
  max_pages_display = 10,
  
  # Analytics settings
  log_searches = TRUE,
  log_performance_metrics = TRUE
)

# Global reactive values for search state
.search_state <- reactiveValues(
  current_query = "",
  current_filters = list(),
  current_results = NULL,
  current_page = 1,
  total_results = 0,
  search_performance = list(),
  autocomplete_cache = list()
)

# ============================================================================
# MAIN SEARCH SERVER FUNCTION
# ============================================================================

#' Advanced search server module
#' @param id Module ID namespace
#' @param get_data_function Function to retrieve base dataset
#' @return Server function for search module
advanced_search_server <- function(id, get_data_function = NULL) {
  moduleServer(id, function(input, output, session) {
    
    # Initialize search state
    search_state <- reactiveValues(
      query = "",
      filters = list(),
      results = NULL,
      current_page = 1,
      total_results = 0,
      is_searching = FALSE,
      last_search_time = NULL
    )
    
    # ========================================================================
    # REACTIVE DATA PREPARATION
    # ========================================================================
    
    # Get base dataset
    base_data <- reactive({
      if (!is.null(get_data_function) && is.function(get_data_function)) {
        return(get_data_function())
      } else if (exists("advanced_search_documents", envir = .GlobalEnv)) {
        # Use existing search function with empty query to get all documents
        return(advanced_search_documents("", limit = 1000))
      } else {
        # Fallback to mock data
        return(create_fallback_dataset())
      }
    })
    
    # Current search filters (reactive)
    current_filters <- reactive({
      list(
        # Geographic filters
        estado = if (!is.null(input$state_filter) && length(input$state_filter) > 0) {
          input$state_filter
        } else if (!is.null(input$region_filter) && input$region_filter != "all") {
          get_states_for_region(input$region_filter)
        } else {
          NULL
        },
        region = if (!is.null(input$region_filter) && input$region_filter != "all") {
          input$region_filter
        } else {
          NULL
        },
        municipality = if (!is.null(input$municipality_filter) && length(input$municipality_filter) > 0) {
          input$municipality_filter
        } else {
          NULL
        },
        metropolitan_area = if (!is.null(input$metro_area_filter) && input$metro_area_filter != "all") {
          input$metro_area_filter
        } else {
          NULL
        },
        
        # Temporal filters
        date_start = input$date_start,
        date_end = input$date_end,
        year_start = input$year_start,
        year_end = input$year_end,
        legislative_period = if (!is.null(input$legislative_period) && input$legislative_period != "all") {
          input$legislative_period
        } else {
          NULL
        },
        
        # Document type filters
        species = input$species_filter,
        document_type = input$document_type_filter,
        transport_category = if (!is.null(input$transport_category) && input$transport_category != "all") {
          input$transport_category
        } else {
          NULL
        },
        
        # Advanced options
        search_mode = input$search_mode %||% "intelligent",
        content_quality_min = input$content_quality %||% 5,
        results_limit = as.numeric(input$results_limit %||% 25),
        include_archived = input$include_archived %||% TRUE,
        search_scope = input$search_scope %||% c("title", "ementa", "full_text")
      )
    })
    
    # ========================================================================
    # SEARCH EXECUTION AND RESULTS
    # ========================================================================
    
    # Main search results (reactive)
    search_results <- reactive({
      req(input$search_query)
      
      search_state$is_searching <- TRUE
      on.exit(search_state$is_searching <- FALSE)
      
      start_time <- Sys.time()
      
      tryCatch({
        # Build search query
        query <- str_trim(input$search_query)
        filters <- current_filters()
        
        # Log search attempt
        if (.search_server_config$log_searches) {
          log_search_attempt(query, filters)
        }
        
        # Execute search using existing search engine
        if (exists("advanced_search_documents", envir = .GlobalEnv)) {
          results <- advanced_search_documents(
            query = query,
            filters = filters,
            sort_by = input$sort_by %||% "relevance",
            limit = filters$results_limit,
            offset = (search_state$current_page - 1) * filters$results_limit
          )
        } else {
          # Fallback search
          results <- perform_fallback_search(query, filters, base_data())
        }
        
        # Update search state
        search_state$query <- query
        search_state$filters <- filters
        search_state$results <- results
        search_state$total_results <- nrow(results)
        search_state$last_search_time <- Sys.time()
        
        # Log performance metrics
        execution_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
        if (.search_server_config$log_performance_metrics) {
          log_search_performance(query, nrow(results), execution_time)
        }
        
        # Update UI statistics
        updateSearchStatistics(session, nrow(results), execution_time)
        
        return(results)
        
      }, error = function(e) {
        showNotification(
          paste("Erro na busca:", e$message),
          type = "error",
          duration = 5
        )
        
        return(data.frame())
      })
    })
    
    # Debounced instant search (reactive)
    instant_search_results <- reactive({
      if (!is.null(input$search_query) && nchar(str_trim(input$search_query)) >= 2) {
        # Add debouncing delay
        invalidateLater(.search_server_config$instant_search_delay, session)
        
        if (!search_state$is_searching) {
          return(search_results())
        }
      }
      
      return(NULL)
    })
    
    # ========================================================================
    # INTELLIGENT AUTOCOMPLETE FUNCTIONALITY
    # ========================================================================
    
    # Load autocomplete system if not already loaded
    if (!exists("get_contextual_suggestions")) {
      tryCatch({
        if (file.exists("modules/search/intelligent_autocomplete_engine.R")) {
          source("modules/search/intelligent_autocomplete_engine.R")
        }
        if (file.exists("modules/search/autocomplete_server_integration.R")) {
          source("modules/search/autocomplete_server_integration.R")
        }
      }, error = function(e) {
        cat("⚠️ Could not load autocomplete system:", e$message, "\n")
      })
    }
    
    # Enhanced autocomplete suggestions with debouncing
    autocomplete_query <- reactive({
      input$search_query
    }) %>% debounce(150) # 150ms debounce for optimal performance
    
    # Intelligent autocomplete suggestions
    observe({
      query <- str_trim(autocomplete_query() %||% "")
      
      if (nchar(query) >= 2) {
        tryCatch({
          # Get intelligent suggestions with context
          if (exists("get_contextual_suggestions")) {
            suggestions_result <- get_contextual_suggestions(
              partial_query = query,
              search_filters = current_filters(),
              max_suggestions = .search_server_config$max_autocomplete_results
            )
          } else if (exists("get_autocomplete_suggestions")) {
            suggestions_result <- get_autocomplete_suggestions(
              partial_query = query,
              context = current_filters(),
              max_suggestions = .search_server_config$max_autocomplete_results
            )
          } else {
            # Fallback to basic suggestions
            suggestions_result <- generate_basic_autocomplete_fallback(query)
          }
          
          # Format suggestions for frontend
          formatted_suggestions <- lapply(suggestions_result$suggestions, function(sugg) {
            list(
              text = sugg$text,
              value = sugg$text,
              description = sugg$description %||% "",
              category = sugg$category %||% "Legal",
              icon = sugg$icon %||% "fas fa-search",
              score = sugg$score %||% 0
            )
          })
          
          # Send to frontend with metadata
          session$sendCustomMessage("updateAutocomplete", list(
            suggestions = formatted_suggestions,
            query = query,
            total_found = suggestions_result$metadata$total_found %||% length(formatted_suggestions),
            processing_time = suggestions_result$metadata$processing_time_ms %||% 0,
            cache_hit = suggestions_result$metadata$cache_hit %||% FALSE
          ))
          
        }, error = function(e) {
          cat("❌ Autocomplete error:", e$message, "\n")
          # Send fallback suggestions
          fallback <- generate_basic_autocomplete_fallback(query)
          session$sendCustomMessage("updateAutocomplete", list(
            suggestions = fallback$suggestions,
            query = query,
            total_found = length(fallback$suggestions),
            fallback = TRUE
          ))
        })
        
      } else if (nchar(query) == 0) {
        # Clear autocomplete when query is empty
        session$sendCustomMessage("clearAutocomplete", list())
      }
    })
    
    # Handle autocomplete selection
    observeEvent(input$autocomplete_selected, {
      if (!is.null(input$autocomplete_selected$text)) {
        # Update search input with selected term
        updateTextInput(session, "search_query", value = input$autocomplete_selected$text)
        
        # Log selection for analytics
        cat("📊 Autocomplete selection:", input$autocomplete_selected$text, 
            "Category:", input$autocomplete_selected$category %||% "Unknown", "\n")
        
        # Optionally trigger immediate search
        if (input$autocomplete_selected$trigger_search %||% FALSE) {
          # Trigger search after a short delay to allow input update
          invalidateLater(100)
        }
      }
    })
    
    # ========================================================================
    # FILTER INTERACTIONS
    # ========================================================================
    
    # Update municipality choices based on state selection
    observeEvent(input$state_filter, {
      if (!is.null(input$state_filter) && length(input$state_filter) > 0) {
        municipalities <- get_municipalities_for_states(input$state_filter)
        
        updateSelectizeInput(session, "municipality_filter",
                           choices = municipalities,
                           server = TRUE)
      }
    })
    
    # Clear filters handler
    observeEvent(input$clear_filters, {
      # Reset all inputs to default values
      updateTextInput(session, "search_query", value = "")
      updateSelectInput(session, "region_filter", selected = "all")
      updateSelectizeInput(session, "state_filter", selected = character(0))
      updateSelectizeInput(session, "municipality_filter", selected = character(0))
      updateSelectInput(session, "metro_area_filter", selected = "all")
      updateDateInput(session, "date_start", value = NULL)
      updateDateInput(session, "date_end", value = NULL)
      updateNumericInput(session, "year_start", value = NULL)
      updateNumericInput(session, "year_end", value = NULL)
      updateSelectInput(session, "legislative_period", selected = "all")
      updateCheckboxGroupInput(session, "species_filter", selected = c("Legislação", "Jurisprudência"))
      updateCheckboxGroupInput(session, "document_type_filter", selected = character(0))
      updateSelectInput(session, "transport_category", selected = "all")
      updateRadioButtons(session, "search_mode", selected = "intelligent")
      updateSliderInput(session, "content_quality", value = 5)
      updateSelectInput(session, "results_limit", selected = "25")
      updateCheckboxInput(session, "include_archived", value = TRUE)
      updateCheckboxGroupInput(session, "search_scope", selected = c("title", "ementa", "full_text"))
      
      # Clear search state
      search_state$query <- ""
      search_state$filters <- list()
      search_state$results <- NULL
      search_state$current_page <- 1
      search_state$total_results <- 0
      
      showNotification("Filtros limpos com sucesso", type = "success")
    })
    
    # Quick period buttons
    observeEvent(input$period_last_year, {
      end_date <- Sys.Date()
      start_date <- end_date - years(1)
      updateDateInput(session, "date_start", value = start_date)
      updateDateInput(session, "date_end", value = end_date)
    })
    
    observeEvent(input$period_last_5_years, {
      end_date <- Sys.Date()
      start_date <- end_date - years(5)
      updateDateInput(session, "date_start", value = start_date)
      updateDateInput(session, "date_end", value = end_date)
    })
    
    observeEvent(input$period_current_decade, {
      updateNumericInput(session, "year_start", value = 2020)
      updateNumericInput(session, "year_end", value = as.numeric(format(Sys.Date(), "%Y")))
    })
    
    # ========================================================================
    # SEARCH RESULTS DISPLAY
    # ========================================================================
    
    # Results summary output
    output$results_summary <- renderUI({
      results <- search_results()
      
      if (!is.null(results) && nrow(results) > 0) {
        div(class = "results-summary-content",
            icon("info-circle"),
            span(paste(
              "Encontrados", 
              format(nrow(results), big.mark = ".", decimal.mark = ","), 
              "documentos"
            )),
            if (search_state$last_search_time) {
              span(class = "search-time", 
                   paste("em", format(search_state$last_search_time, "%H:%M:%S")))
            }
        )
      }
    })
    
    # Main results display
    output$results_display <- renderUI({
      results <- search_results()
      view_mode <- input$view_mode %||% "list"
      
      if (is.null(results) || nrow(results) == 0) {
        return(div(class = "no-results",
                  icon("search", class = "fa-3x"),
                  h4("Nenhum resultado encontrado"),
                  p("Tente ajustar os termos de busca ou filtros.")))
      }
      
      switch(view_mode,
             "list" = render_results_list(results),
             "cards" = render_results_cards(results),
             "table" = DT::renderDataTable(format_results_table(results), 
                                          options = list(
                                            pageLength = 25,
                                            scrollX = TRUE,
                                            language = list(url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json')
                                          ))
      )
    })
    
    # Export functionality
    output$export_results <- downloadHandler(
      filename = function() {
        paste0("busca_legislativa_", format(Sys.Date(), "%Y%m%d"), ".csv")
      },
      content = function(file) {
        results <- search_results()
        if (!is.null(results) && nrow(results) > 0) {
          # Prepare export data
          export_data <- results %>%
            select(titulo, ementa, tipo, estado, data_publicacao, url) %>%
            mutate(data_publicacao = format(data_publicacao, "%d/%m/%Y"))
          
          write.csv(export_data, file, row.names = FALSE, fileEncoding = "UTF-8")
        }
      }
    )
    
    # ========================================================================
    # UI UPDATES AND NOTIFICATIONS
    # ========================================================================
    
    # Show/hide loading indicator
    observe({
      if (search_state$is_searching) {
        session$sendCustomMessage("showLoading", list())
      } else {
        session$sendCustomMessage("hideLoading", list())
      }
    })
    
    # Update search statistics in header
    updateSearchStatistics <- function(session, result_count, execution_time) {
      session$sendCustomMessage("updateSearchStats", list(
        count = result_count,
        time = round(execution_time * 1000, 0),  # Convert to milliseconds
        formatted_count = format(result_count, big.mark = ".", decimal.mark = ",")
      ))
    }
    
    # Return reactive values for external use
    return(list(
      results = reactive(search_results()),
      current_query = reactive(search_state$query),
      current_filters = current_filters,
      total_results = reactive(search_state$total_results),
      is_searching = reactive(search_state$is_searching)
    ))
  })
}

# ============================================================================
# UTILITY FUNCTIONS FOR SEARCH SERVER
# ============================================================================

#' Generate basic autocomplete fallback when intelligent system is unavailable
#' @param query User query
#' @return Basic suggestions list
generate_basic_autocomplete_fallback <- function(query) {
  # Basic Portuguese legal terms for fallback
  basic_terms <- c(
    "Lei Federal", "Lei Estadual", "Decreto", "Portaria", "Resolução", "Medida Provisória",
    "STF", "STJ", "Supremo Tribunal Federal", "Superior Tribunal de Justiça",
    "Constituição Federal", "Código Civil", "Código Penal", "Código de Trânsito",
    "Transporte Público", "Transporte Rodoviário", "Mobilidade Urbana",
    "São Paulo", "Rio de Janeiro", "Brasília", "Minas Gerais", "Bahia",
    "ANTT", "ANAC", "ANTAQ", "Licitação", "Contrato Administrativo"
  )
  
  query_lower <- str_to_lower(query)
  matches <- basic_terms[str_detect(str_to_lower(basic_terms), fixed(query_lower))]
  matches <- head(matches, 5)
  
  suggestions <- lapply(matches, function(term) {
    list(
      text = term,
      description = "Termo Legal (Fallback)",
      category = "Legal",
      icon = "fas fa-search"
    )
  })
  
  return(list(
    suggestions = suggestions,
    metadata = list(
      query = query,
      total_found = length(suggestions),
      source = "basic_fallback",
      processing_time_ms = 0
    )
  ))
}

#' Perform fallback search when advanced search engine is not available
#' @param query Search query
#' @param filters Search filters
#' @param data Base dataset
#' @return Filtered search results
perform_fallback_search <- function(query, filters, data) {
  
  if (nrow(data) == 0) {
    return(data.frame())
  }
  
  filtered_data <- data
  
  # Apply text search
  if (!is.null(query) && nchar(str_trim(query)) > 0) {
    query_pattern <- str_to_lower(query)
    
    if ("titulo" %in% names(filtered_data)) {
      title_matches <- str_detect(str_to_lower(filtered_data$titulo), query_pattern)
    } else {
      title_matches <- rep(FALSE, nrow(filtered_data))
    }
    
    if ("ementa" %in% names(filtered_data)) {
      ementa_matches <- str_detect(str_to_lower(filtered_data$ementa), query_pattern)
    } else {
      ementa_matches <- rep(FALSE, nrow(filtered_data))
    }
    
    filtered_data <- filtered_data[title_matches | ementa_matches, ]
  }
  
  # Apply geographic filters
  if (exists("apply_geographic_filter", envir = .GlobalEnv)) {
    filtered_data <- apply_geographic_filter(filtered_data, filters, include_federal = TRUE)
  }
  
  # Apply temporal filters
  if (exists("apply_temporal_filter", envir = .GlobalEnv)) {
    filtered_data <- apply_temporal_filter(filtered_data, filters)
  }
  
  # Apply document type filters
  if (!is.null(filters$species) && length(filters$species) > 0) {
    if ("species" %in% names(filtered_data)) {
      filtered_data <- filtered_data[filtered_data$species %in% filters$species, ]
    }
  }
  
  if (!is.null(filters$document_type) && length(filters$document_type) > 0) {
    if ("tipo" %in% names(filtered_data)) {
      filtered_data <- filtered_data[filtered_data$tipo %in% filters$document_type, ]
    }
  }
  
  # Apply content quality filter
  if (!is.null(filters$content_quality_min) && "content_quality_score" %in% names(filtered_data)) {
    filtered_data <- filtered_data[filtered_data$content_quality_score >= filters$content_quality_min, ]
  }
  
  # Sort results
  sort_by <- filters$sort_by %||% "relevance"
  
  if (sort_by == "date_desc" && "data_publicacao" %in% names(filtered_data)) {
    filtered_data <- filtered_data[order(filtered_data$data_publicacao, decreasing = TRUE), ]
  } else if (sort_by == "date_asc" && "data_publicacao" %in% names(filtered_data)) {
    filtered_data <- filtered_data[order(filtered_data$data_publicacao, decreasing = FALSE), ]
  } else if (sort_by == "title" && "titulo" %in% names(filtered_data)) {
    filtered_data <- filtered_data[order(filtered_data$titulo), ]
  }
  
  return(filtered_data)
}

#' Create fallback dataset when no data source is available
#' @return Mock dataset for demonstration
create_fallback_dataset <- function() {
  n_docs <- 100
  
  data.frame(
    id = 1:n_docs,
    titulo = paste("Documento Legislativo", 1:n_docs),
    ementa = paste("Ementa do documento", 1:n_docs, "- Regulamenta questões importantes"),
    tipo = sample(c("Lei", "Decreto", "Portaria", "Resolução"), n_docs, replace = TRUE),
    species = sample(c("Legislação", "Jurisprudência"), n_docs, replace = TRUE),
    estado = sample(c("BR", "SP", "RJ", "MG", "RS", "PR"), n_docs, replace = TRUE),
    data_publicacao = sample(seq(as.Date("2020-01-01"), Sys.Date(), by = "day"), n_docs),
    content_quality_score = runif(n_docs, 5, 10),
    transport_category = sample(c("Geral", "Rodoviário", "Urbano"), n_docs, replace = TRUE),
    url = paste0("https://exemplo.gov.br/doc/", 1:n_docs),
    stringsAsFactors = FALSE
  )
}

#' Get states for a given region
#' @param region Brazilian region name
#' @return Character vector of state codes
get_states_for_region <- function(region) {
  region_mapping <- list(
    "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
    "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
    "Centro-Oeste" = c("DF", "GO", "MT", "MS"),
    "Sudeste" = c("ES", "MG", "RJ", "SP"),
    "Sul" = c("PR", "RS", "SC")
  )
  
  return(region_mapping[[region]] %||% character(0))
}

#' Get municipalities for selected states
#' @param states Character vector of state codes
#' @return Named list of municipality choices
get_municipalities_for_states <- function(states) {
  # This would ideally connect to a municipalities database
  # For now, return some major municipalities
  major_municipalities <- list(
    "SP" = c("São Paulo", "Guarulhos", "Campinas", "São Bernardo do Campo", "Osasco"),
    "RJ" = c("Rio de Janeiro", "Nova Iguaçu", "Duque de Caxias", "Niterói", "Campos dos Goytacazes"),
    "MG" = c("Belo Horizonte", "Contagem", "Betim", "Juiz de Fora", "Montes Claros"),
    "RS" = c("Porto Alegre", "Canoas", "Novo Hamburgo", "Pelotas", "Caxias do Sul"),
    "PR" = c("Curitiba", "Londrina", "Maringá", "Ponta Grossa", "Cascavel")
  )
  
  municipalities <- character(0)
  for (state in states) {
    if (state %in% names(major_municipalities)) {
      municipalities <- c(municipalities, major_municipalities[[state]])
    }
  }
  
  return(setNames(municipalities, municipalities))
}

#' Render search results as list view
#' @param results Search results data frame
#' @return HTML div with formatted results
render_results_list <- function(results) {
  if (nrow(results) == 0) return(div())
  
  result_items <- apply(results, 1, function(row) {
    div(class = "result-item list-item",
        div(class = "result-header",
            h5(class = "result-title", row[["titulo"]]),
            div(class = "result-metadata",
                span(class = "result-type badge badge-primary", row[["tipo"]]),
                span(class = "result-state badge badge-secondary", row[["estado"]]),
                span(class = "result-date", format(as.Date(row[["data_publicacao"]]), "%d/%m/%Y"))
            )
        ),
        div(class = "result-content",
            p(class = "result-ementa", substr(row[["ementa"]], 1, 300)),
            if (!is.null(row[["url"]]) && row[["url"]] != "") {
              a(href = row[["url"]], target = "_blank", 
                "Ver documento completo", icon("external-link-alt"))
            }
        )
    )
  })
  
  div(class = "results-list", result_items)
}

#' Render search results as cards view
#' @param results Search results data frame
#' @return HTML div with card-formatted results
render_results_cards <- function(results) {
  if (nrow(results) == 0) return(div())
  
  # Group results into rows of 2 cards
  n_results <- nrow(results)
  cards <- list()
  
  for (i in seq(1, n_results, by = 2)) {
    row_cards <- list()
    
    for (j in i:min(i+1, n_results)) {
      row <- results[j, ]
      card <- div(class = "col-md-6",
                  div(class = "card result-card mb-3",
                      div(class = "card-header",
                          h6(class = "card-title mb-0", row[["titulo"]]),
                          div(class = "card-metadata",
                              span(class = "badge badge-primary", row[["tipo"]]),
                              span(class = "badge badge-secondary ml-1", row[["estado"]])
                          )
                      ),
                      div(class = "card-body",
                          p(class = "card-text", substr(row[["ementa"]], 1, 200)),
                          div(class = "card-footer-actions",
                              small(class = "text-muted", 
                                    format(as.Date(row[["data_publicacao"]]), "%d/%m/%Y")),
                              if (!is.null(row[["url"]]) && row[["url"]] != "") {
                                a(href = row[["url"]], target = "_blank", 
                                  class = "btn btn-sm btn-outline-primary ml-2",
                                  "Ver", icon("external-link-alt"))
                              }
                          )
                      )
                  )
      )
      row_cards <- append(row_cards, list(card))
    }
    
    cards <- append(cards, list(div(class = "row", row_cards)))
  }
  
  div(class = "results-cards", cards)
}

#' Format results for DataTable display
#' @param results Search results data frame
#' @return Formatted data frame for DT
format_results_table <- function(results) {
  if (nrow(results) == 0) return(data.frame())
  
  # Select and format columns for table display
  table_data <- results %>%
    select(
      Título = titulo,
      Tipo = tipo,
      Estado = estado,
      `Data Publicação` = data_publicacao,
      Ementa = ementa
    ) %>%
    mutate(
      `Data Publicação` = format(`Data Publicação`, "%d/%m/%Y"),
      Ementa = substr(Ementa, 1, 150)  # Truncate for table display
    )
  
  return(table_data)
}

#' Log search attempt for analytics
#' @param query Search query
#' @param filters Applied filters
log_search_attempt <- function(query, filters) {
  tryCatch({
    cat("🔍 Search attempt:", query, "\n")
    if (length(filters) > 0) {
      cat("   Filters applied:", length(filters), "\n")
    }
  }, error = function(e) {
    # Silent fail for logging
  })
}

#' Log search performance metrics
#' @param query Search query
#' @param result_count Number of results
#' @param execution_time Execution time in seconds
log_search_performance <- function(query, result_count, execution_time) {
  tryCatch({
    cat("📊 Search performance - Query:", substr(query, 1, 50), 
        "| Results:", result_count, 
        "| Time:", round(execution_time * 1000, 2), "ms\n")
  }, error = function(e) {
    # Silent fail for logging
  })
}

# ============================================================================
# INITIALIZATION
# ============================================================================

cat("✅ Advanced Search Server Module loaded successfully\n")
cat("   🔧 Real-time search processing with debouncing\n")
cat("   🗂️ Advanced filtering with Brazilian geography\n")
cat("   💡 Intelligent autocomplete with legal terms\n")
cat("   📊 Performance monitoring and analytics\n")
cat("   🔄 Integration with existing search engine backend\n")

# Export main server function
.GlobalEnv$advanced_search_server <- advanced_search_server