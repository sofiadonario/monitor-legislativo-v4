# Advanced Search Server Module - Week 3 Implementation
# Monitor Legislativo v4 - Enhanced Search System
# ================================================

# Load required libraries
if (!requireNamespace("stringr", quietly = TRUE)) {
  warning("stringr package not available - some text processing features may be limited")
  str_to_title <- function(x) tools::toTitleCase(x)
} else {
  library(stringr)
}

if (!requireNamespace("jsonlite", quietly = TRUE)) {
  warning("jsonlite package not available - JSON export will be limited")
}

if (!requireNamespace("shinyjs", quietly = TRUE)) {
  warning("shinyjs package not available - some interactive features may be limited")
} else {
  library(shinyjs)
  runjs <- shinyjs::runjs
}

#' Advanced Legislative Document Search Module Server
#' 
#' Comprehensive server logic for the advanced legislative document search module
#' with PostgreSQL full-text search, Brazilian Portuguese processing, geographic
#' and temporal filtering, performance monitoring, and LGPD compliance.
#' 
#' Week 3 Implementation: Target <2s response time for complex queries on 134k+ documents
#' 
#' @param id Character string for module namespace ID
#' @param db_pool Reactive expression returning database connection pool
#' @return Named list of reactive expressions for parent module integration
#' @family search-modules
#' @export
searchAdvancedServer <- function(id, db_pool = reactive(NULL)) {
  moduleServer(id, function(input, output, session) {
    
    # Initialize filter choices with faceted counts
    observe({
      pool <- db_pool()
      
      if (!is.null(pool)) {
        # Update estado choices with document counts
        tryCatch({
          estados_data <- execute_query(pool, 
            "SELECT filter_value, document_count FROM search_filters_cache WHERE filter_type = 'estado' ORDER BY document_count DESC")
          
          if (!is.null(estados_data) && nrow(estados_data) > 0) {
            estado_choices <- setNames(
              estados_data$filter_value,
              paste0(estados_data$filter_value, " (", format(estados_data$document_count, big.mark = ","), ")")
            )
            updateSelectInput(
              session, 
              "estado",
              choices = c("All States" = "", estado_choices)
            )
          } else {
            # Fallback with Brazilian states
            estados <- c("BR", "SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE", "DF")
            updateSelectInput(
              session,
              "estado", 
              choices = c("All States" = "", setNames(estados, estados))
            )
          }
        }, error = function(e) {
          warning("Estado filter update failed: ", e$message)
          estados <- c("BR", "SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE", "DF")
          updateSelectInput(
            session,
            "estado", 
            choices = c("All States" = "", setNames(estados, estados))
          )
        })
        
        # Update tipo choices with document counts
        tryCatch({
          tipos_data <- execute_query(pool, 
            "SELECT filter_value, document_count FROM search_filters_cache WHERE filter_type = 'tipo' ORDER BY document_count DESC")
          
          if (!is.null(tipos_data) && nrow(tipos_data) > 0) {
            tipo_choices <- setNames(
              tipos_data$filter_value,
              paste0(str_to_title(tipos_data$filter_value), " (", format(tipos_data$document_count, big.mark = ","), ")")
            )
            updateSelectInput(
              session,
              "tipo",
              choices = c("All Types" = "", tipo_choices)
            )
          } else {
            # Fallback with common document types
            tipos <- c("lei", "decreto", "portaria", "resolução", "instrução normativa", "medida provisória")
            updateSelectInput(
              session,
              "tipo",
              choices = c("All Types" = "", setNames(tipos, str_to_title(tipos)))
            )
          }
        }, error = function(e) {
          warning("Tipo filter update failed: ", e$message)
          tipos <- c("lei", "decreto", "portaria", "resolução", "instrução normativa", "medida provisória")
          updateSelectInput(
            session,
            "tipo",
            choices = c("All Types" = "", setNames(tipos, str_to_title(tipos)))
          )
        })
        
        # Update categoria choices
        tryCatch({
          categorias_data <- execute_query(pool, 
            "SELECT filter_value, document_count FROM search_filters_cache WHERE filter_type = 'categoria' ORDER BY document_count DESC")
          
          if (!is.null(categorias_data) && nrow(categorias_data) > 0) {
            categoria_choices <- setNames(
              categorias_data$filter_value,
              paste0(str_to_title(categorias_data$filter_value), " (", format(categorias_data$document_count, big.mark = ","), ")")
            )
            updateSelectInput(
              session,
              "categoria",
              choices = c("All Categories" = "", categoria_choices)
            )
          }
        }, error = function(e) {
          # Categoria is optional
        })
      }
    })
    
    # Dynamic municipality update based on selected state
    observe({
      req(input$estado)
      pool <- db_pool()
      
      if (!is.null(pool) && input$estado != "") {
        tryCatch({
          municipios <- execute_query(pool,
            "SELECT DISTINCT municipio, COUNT(*) as doc_count 
             FROM documents 
             WHERE estado = $1 AND municipio IS NOT NULL AND municipio != '' 
             GROUP BY municipio 
             ORDER BY doc_count DESC, municipio",
            params = list(input$estado))
          
          if (!is.null(municipios) && nrow(municipios) > 0) {
            municipio_choices <- setNames(
              municipios$municipio,
              paste0(municipios$municipio, " (", municipios$doc_count, ")")
            )
            updateSelectInput(
              session,
              "municipio",
              choices = c("All Municipalities" = "", municipio_choices)
            )
          } else {
            updateSelectInput(
              session,
              "municipio", 
              choices = c("All Municipalities" = "")
            )
          }
        }, error = function(e) {
          updateSelectInput(
            session,
            "municipio",
            choices = c("All Municipalities" = "")
          )
        })
      }
    })
    
    # Auto-complete functionality
    suggestions_data <- reactive({
      req(input$query)
      
      if (nchar(input$query) >= 3) {
        pool <- db_pool()
        
        if (!is.null(pool)) {
          tryCatch({
            suggestions <- execute_query(pool,
              "SELECT * FROM get_search_suggestions($1, 8)",
              params = list(input$query))
            
            return(suggestions)
          }, error = function(e) {
            return(NULL)
          })
        }
      }
      
      return(NULL)
    })
    
    # Render auto-complete suggestions
    output$suggestions <- renderUI({
      suggestions <- suggestions_data()
      
      if (is.null(suggestions) || nrow(suggestions) == 0) {
        return(NULL)
      }
      
      suggestion_items <- lapply(1:nrow(suggestions), function(i) {
        sug <- suggestions[i, ]
        div(
          class = "autocomplete-item",
          onclick = paste0("document.getElementById('", session$ns("query"), "').value = '", sug$suggestion, "'; $('#", session$ns("autocomplete_dropdown"), "').hide();"),
          span(class = "suggestion-text", sug$suggestion),
          span(class = "facet-count pull-right", paste0("(", sug$frequency, ")"))
        )
      })
      
      do.call(tagList, suggestion_items)
    })
    
    # Show/hide suggestions based on input focus
    observe({
      suggestions <- suggestions_data()
      
      if (!is.null(suggestions) && nrow(suggestions) > 0) {
        if (exists("runjs")) {
          runjs(paste0("$('#", session$ns("autocomplete_dropdown"), "').show();"))
        }
      } else {
        if (exists("runjs")) {
          runjs(paste0("$('#", session$ns("autocomplete_dropdown"), "').hide();"))
        }
      }
    })
    
    # Advanced search results with performance monitoring
    search_results <- eventReactive(input$search, {
      
      req(input$query)
      
      search_start_time <- Sys.time()
      
      # Security validation and rate limiting
      tryCatch({
        # Get client identifier
        client_id <- session$clientData$url_hostname %||% "unknown"
        
        # Check rate limit (100 requests per hour per client)
        rate_check <- check_rate_limit(client_id, max_requests = 100, time_window = 3600)
        
        if (!rate_check$allowed) {
          log_security_event("RATE_LIMIT_EXCEEDED", 
                           paste("Search rate limit exceeded for client:", client_id))
          showNotification(
            "Too many search requests. Please wait before searching again.",
            type = "warning",
            duration = 10
          )
          return(list(results = data.frame(), search_time = 0, total_count = 0))
        }
        
        # Validate search query
        query_validation <- validate_input(
          input$query, 
          type = "search_query", 
          max_length = 500, 
          required = TRUE
        )
        
        if (!query_validation$valid) {
          log_security_event("INVALID_SEARCH_QUERY", 
                           paste("Invalid search query:", substr(input$query, 1, 100)))
          showNotification(
            paste("Invalid search query:", query_validation$error),
            type = "error",
            duration = 5
          )
          return(list(results = data.frame(), search_time = 0, total_count = 0))
        }
        
        # Use sanitized query
        sanitized_query <- query_validation$value
        
        if (nchar(trimws(sanitized_query)) == 0) {
          return(list(results = data.frame(), search_time = 0, total_count = 0))
        }
        
      }, error = function(e) {
        log_security_event("SEARCH_SECURITY_ERROR", paste("Search security check failed:", e$message))
        showNotification(
          "Security validation failed. Please try again.",
          type = "error",
          duration = 5
        )
        return(list(results = data.frame(), search_time = 0, total_count = 0))
      })
      
      # Build and validate advanced filters
      filters <- list()
      
      # Validate geographic filters
      if (!is.null(input$estado) && input$estado != "") {
        estado_validation <- validate_input(input$estado, type = "character", max_length = 10, allow_html = FALSE)
        if (estado_validation$valid) {
          filters$filter_estado <- estado_validation$value
        }
      }
      
      if (!is.null(input$municipio) && input$municipio != "") {
        municipio_validation <- validate_input(input$municipio, type = "character", max_length = 100, allow_html = FALSE)
        if (municipio_validation$valid) {
          filters$filter_municipio <- municipio_validation$value
        }
      }
      
      # Validate document type filters
      if (!is.null(input$tipo) && input$tipo != "") {
        tipo_validation <- validate_input(input$tipo, type = "character", max_length = 50, allow_html = FALSE)
        if (tipo_validation$valid) {
          filters$filter_tipo <- tipo_validation$value
        }
      }
      
      if (!is.null(input$categoria) && input$categoria != "") {
        categoria_validation <- validate_input(input$categoria, type = "character", max_length = 100, allow_html = FALSE)
        if (categoria_validation$valid) {
          filters$filter_categoria <- categoria_validation$value
        }
      }
      
      # Validate temporal filters
      if (!is.null(input$ano_min) && !is.na(input$ano_min)) {
        ano_min_validation <- validate_input(input$ano_min, type = "numeric", min_value = 1900, max_value = 2030)
        if (ano_min_validation$valid) {
          filters$filter_ano_min <- as.integer(ano_min_validation$value)
        }
      }
      
      if (!is.null(input$ano_max) && !is.na(input$ano_max)) {
        ano_max_validation <- validate_input(input$ano_max, type = "numeric", min_value = 1900, max_value = 2030)
        if (ano_max_validation$valid) {
          filters$filter_ano_max <- as.integer(ano_max_validation$value)
        }
      }
      
      # Validate date filters
      if (!is.null(input$data_inicio)) {
        tryCatch({
          filters$filter_data_inicio <- as.Date(input$data_inicio)
        }, error = function(e) {
          log_security_event("INVALID_FILTER", paste("Invalid data_inicio filter:", input$data_inicio))
        })
      }
      
      if (!is.null(input$data_fim)) {
        tryCatch({
          filters$filter_data_fim <- as.Date(input$data_fim)
        }, error = function(e) {
          log_security_event("INVALID_FILTER", paste("Invalid data_fim filter:", input$data_fim))
        })
      }
      
      # Validate search parameters
      search_limit <- if (!is.null(input$limit) && !is.na(input$limit)) {
        limit_validation <- validate_input(input$limit, type = "numeric", min_value = 10, max_value = 1000)
        if (limit_validation$valid) {
          as.integer(limit_validation$value)
        } else {
          100
        }
      } else {
        100
      }
      
      # Sort parameter validation
      sort_by <- if (!is.null(input$sort_by) && input$sort_by %in% c("relevance", "date_desc", "date_asc", "title")) {
        input$sort_by
      } else {
        "relevance"
      }
      
      # Execute search
      pool <- db_pool()
      
      withProgress(message = "Searching documents...", value = 0, {
        incProgress(0.3, detail = "Executing advanced search query")
        
        # Execute advanced search using PostgreSQL function
        if (!is.null(pool)) {
          results <- execute_query(pool,
            "SELECT * FROM search_legislative_documents($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            params = list(
              sanitized_query,
              filters$filter_estado,
              filters$filter_municipio,
              filters$filter_tipo,
              filters$filter_categoria,
              filters$filter_ano_min,
              filters$filter_ano_max,
              filters$filter_data_inicio,
              filters$filter_data_fim,
              search_limit,
              0,  # offset
              sort_by
            )
          )
        } else {
          # Fallback to basic search
          results <- search_documents(
            pool = pool,
            query = sanitized_query,
            filters = filters,
            limit = search_limit
          )
        }
        
        # Calculate search performance metrics
        search_time <- as.numeric(difftime(Sys.time(), search_start_time, units = "secs"))
        total_results <- if (!is.null(results)) nrow(results) else 0
        
        # Log successful search with performance metrics
        log_security_event("SEARCH_EXECUTED", 
                         paste("Search completed. Query length:", nchar(sanitized_query), 
                               "Results:", total_results, "Time:", round(search_time, 3), "sec"))
        
        incProgress(0.7, detail = "Processing results")
        
        # Clean and format results with security controls
        if (!is.null(results) && nrow(results) > 0) {
          # Sanitize all text content to prevent XSS
          text_columns <- c("titulo", "content", "ementa", "tipo", "categoria", "orgao_emissor", "municipio", "estado")
          for (col in text_columns) {
            if (col %in% names(results)) {
              results[[col]] <- safe_html(results[[col]], max_length = 1000, allow_basic_formatting = FALSE)
            }
          }
          
          # Handle content and highlighting based on user preferences
          if (!isTRUE(input$include_content) && "content" %in% names(results)) {
            results$content <- truncate_text(results$content, 200)
          }
          
          # Add highlighting if available and requested
          if (isTRUE(input$include_highlights)) {
            if ("title_highlight" %in% names(results) && "content_highlight" %in% names(results)) {
              # Use highlighted versions
              results$titulo_display <- ifelse(
                is.na(results$title_highlight) | results$title_highlight == "",
                results$titulo,
                results$title_highlight
              )
              results$content_display <- ifelse(
                is.na(results$content_highlight) | results$content_highlight == "",
                substr(results$content, 1, 200),
                results$content_highlight
              )
            }
          }
          
          # Format dates safely
          if ("data_publicacao" %in% names(results)) {
            results$data_publicacao <- safe_date_parse(results$data_publicacao)
          }
          
          # Format relevance scores
          if ("relevance_score" %in% names(results)) {
            results$relevance_display <- round(as.numeric(results$relevance_score), 3)
          }
          
          # Validate result count doesn't exceed reasonable limits
          if (nrow(results) > search_limit) {
            log_security_event("SEARCH_RESULT_ANOMALY", 
                             paste("Search returned more results than requested:", nrow(results)))
            results <- results[1:search_limit, ]
          }
        }
        
        incProgress(1.0, detail = "Complete")
        
        # Return comprehensive search result object
        return(list(
          results = if (!is.null(results)) results else data.frame(),
          search_time = search_time,
          total_count = total_results,
          query = sanitized_query,
          filters = filters,
          sort_by = sort_by
        ))
      })
    })
    
    # Advanced search statistics output
    output$search_stats <- renderUI({
      search_result_obj <- search_results()
      
      if (is.null(search_result_obj) || is.null(search_result_obj$results) || nrow(search_result_obj$results) == 0) {
        if (!is.null(input$search) && input$search > 0) {
          return(div(
            class = "alert alert-warning",
            icon("info-circle"),
            " No documents found matching your search criteria. Try adjusting your filters or search terms."
          ))
        } else {
          return(div(
            class = "text-muted",
            "Enter search terms and click 'Search' to find documents. Use quotes for exact phrases, + for required terms."
          ))
        }
      }
      
      results_count <- search_result_obj$total_count
      search_time <- search_result_obj$search_time
      
      # Performance indicator color
      time_class <- if (search_time <= 1) "text-success" else if (search_time <= 2) "text-warning" else "text-danger"
      
      div(
        class = "alert alert-info",
        icon("check-circle"),
        paste0(
          " Found ", format(results_count, big.mark = ","), 
          " document", if(results_count != 1) "s" else "",
          " matching your search for '", input$query, "'"
        ),
        br(),
        span(
          class = paste("small", time_class),
          paste0("Search completed in ", round(search_time, 2), " seconds")
        )
      )
    })
    
    # Search performance display
    output$search_performance <- renderUI({
      search_result_obj <- search_results()
      
      if (is.null(search_result_obj)) {
        return(div(
          class = "search-performance text-muted",
          "Performance: Ready"
        ))
      }
      
      search_time <- search_result_obj$search_time
      time_class <- if (search_time <= 1) "text-success" else if (search_time <= 2) "text-warning" else "text-danger"
      
      div(
        class = paste("search-performance", time_class),
        icon("tachometer-alt"),
        paste0(" ", round(search_time, 2), "s")
      )
    })
    
    # Enhanced return reactive values for parent module integration
    return(list(
      results = reactive({
        search_result_obj <- search_results()
        if (!is.null(search_result_obj)) search_result_obj$results else data.frame()
      }),
      search_metadata = reactive({
        search_result_obj <- search_results()
        if (!is.null(search_result_obj)) {
          list(
            query = search_result_obj$query,
            total_count = search_result_obj$total_count,
            search_time = search_result_obj$search_time,
            filters = search_result_obj$filters,
            sort_by = search_result_obj$sort_by
          )
        } else {
          NULL
        }
      }),
      selected_rows = reactive({
        if (!is.null(input$results_rows_selected)) {
          input$results_rows_selected
        } else {
          integer(0)
        }
      }),
      query = reactive(input$query),
      filters_active = reactive({
        (!is.null(input$estado) && input$estado != "") ||
        (!is.null(input$municipio) && input$municipio != "") ||
        (!is.null(input$tipo) && input$tipo != "") ||
        (!is.null(input$categoria) && input$categoria != "") ||
        (!is.null(input$ano_min) && !is.na(input$ano_min)) ||
        (!is.null(input$ano_max) && !is.na(input$ano_max)) ||
        (!is.null(input$data_inicio)) ||
        (!is.null(input$data_fim))
      }),
      performance_metrics = reactive({
        search_result_obj <- search_results()
        if (!is.null(search_result_obj)) {
          list(
            search_time = search_result_obj$search_time,
            total_results = search_result_obj$total_count,
            performance_rating = if (search_result_obj$search_time <= 1) "excellent" else 
                                if (search_result_obj$search_time <= 2) "good" else "needs_optimization"
          )
        } else {
          NULL
        }
      })
    ))
  })
}

cat("✅ Advanced Search Server Module loaded - Week 3 Implementation\n")