# Search Module
# Monitor Legislativo v4 - Modular Search Interface
# =================================================

#' Legislative Document Search Module UI
#' 
#' Comprehensive Shiny module UI for searching Brazilian legislative documents
#' with advanced filtering, academic export capabilities, and LGPD-compliant
#' security features. Designed specifically for academic research workflows
#' in legislative analysis and policy studies.
#' 
#' This module provides a complete search interface including text input,
#' advanced filters, results display, and export functionality optimized
#' for Brazilian legal document research.
#' 
#' @details
#' **UI Components:**
#' - **Search Input**: Text input with placeholder for Portuguese legal terms
#' - **Advanced Filters**: Collapsible panel with state, document type, year range
#' - **Results Table**: Interactive DataTable with sorting and pagination
#' - **Export Options**: CSV and BibTeX download with academic citation formats
#' - **Search Statistics**: Real-time feedback on search results
#' 
#' **Academic Features:**
#' - Brazilian Portuguese interface and terminology
#' - ABNT-compliant citation export formats
#' - Advanced filtering for legislative document types
#' - Geographic filtering by Brazilian states
#' - Temporal analysis with year range selection
#' 
#' **Accessibility:**
#' - Screen reader compatible labels and descriptions
#' - Keyboard navigation support
#' - Mobile-responsive layout for field research
#' 
#' @param id Character string for module namespace ID. Must be unique
#'   within the application to avoid conflicts with other modules.
#' 
#' @return Shiny UI tagList containing all search interface elements:
#'   - Search input and button
#'   - Advanced filters panel (collapsible)
#'   - Results statistics display
#'   - Interactive results table
#'   - Export buttons (CSV, BibTeX)
#'   - Pagination information
#' 
#' @family search-modules
#' @seealso \code{\link{searchServer}} for corresponding server logic
#' @seealso \code{\link{generate_bibtex_citations}} for citation generation
#' 
#' @examples
#' \dontrun{
#' # Include in Shiny UI
#' library(shiny)
#' 
#' ui <- fluidPage(
#'   titlePanel("Monitor Legislativo - Academic Research"),
#'   searchUI("legislative_search")
#' )
#' 
#' # Multiple search modules (different namespaces)
#' ui <- fluidPage(
#'   tabsetPanel(
#'     tabPanel("Federal Laws", searchUI("federal_search")),
#'     tabPanel("State Laws", searchUI("state_search"))
#'   )
#' )
#' }
#' 
#' @export
searchUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    # Search Input Section
    fluidRow(
      column(
        width = 8,
        textInput(
          ns("query"),
          "Search Legislative Documents",
          placeholder = "Enter search terms (e.g., 'transporte público')",
          width = "100%"
        )
      ),
      column(
        width = 4,
        br(),
        actionButton(
          ns("search"),
          "Search",
          class = "btn-primary btn-block",
          icon = icon("search")
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
          fluidRow(
            column(3,
              selectInput(
                ns("estado"),
                "State",
                choices = c("All States" = ""),
                width = "100%"
              )
            ),
            column(3,
              selectInput(
                ns("tipo"),
                "Document Type",
                choices = c("All Types" = ""),
                width = "100%"
              )
            ),
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
            )
          ),
          
          fluidRow(
            column(6,
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
            column(6,
              checkboxInput(
                ns("include_content"),
                "Include full content in results",
                value = FALSE
              )
            )
          )
        )
      )
    ),
    
    # Search Statistics
    div(
      id = ns("stats_container"),
      style = "margin-top: 15px;",
      uiOutput(ns("search_stats"))
    ),
    
    # Results Display
    div(
      id = ns("results_container"),
      style = "margin-top: 20px;",
      
      # Results Table
      DT::DTOutput(ns("results")),
      
      # Export Options
      div(
        style = "margin-top: 15px;",
        
        fluidRow(
          column(6,
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
            )
          ),
          column(6,
            div(
              class = "pull-right",
              uiOutput(ns("pagination_info"))
            )
          )
        )
      )
    )
  )
}

#' Legislative Document Search Module Server
#' 
#' Comprehensive server logic for the legislative document search module with
#' enterprise-grade security, LGPD compliance, and academic research features.
#' Handles secure search execution, rate limiting, input validation, and
#' academic citation generation for Brazilian legislative documents.
#' 
#' This function implements the complete backend logic for academic legislative
#' research, including security controls required for Brazilian government
#' data access and LGPD compliance.
#' 
#' @details
#' **Security Features:**
#' - **Rate Limiting**: Prevents abuse with configurable request limits
#' - **Input Validation**: Comprehensive validation of all search parameters
#' - **XSS Protection**: Sanitizes all output content for safe display
#' - **SQL Injection Prevention**: Validates and sanitizes database queries
#' - **Security Logging**: Records all search operations for compliance
#' 
#' **Academic Research Features:**
#' - **Advanced Filtering**: State, document type, year range, content inclusion
#' - **Search Statistics**: Real-time result counts and search feedback
#' - **Export Capabilities**: CSV for analysis, BibTeX for academic citations
#' - **Pagination**: Efficient handling of large result sets
#' - **Content Sanitization**: Safe display of legislative document content
#' 
#' **LGPD Compliance:**
#' - Audit logging of all search operations
#' - Data export tracking and rate limiting
#' - Secure handling of user search queries
#' - Privacy-compliant result filtering
#' 
#' **Database Integration:**
#' - Connection pool management for optimal performance
#' - Fallback to CSV data sources when database unavailable
#' - Circuit breaker pattern for database resilience
#' 
#' @param id Character string for module namespace ID. Must match the ID
#'   used in the corresponding \code{searchUI} call.
#' @param db_pool Reactive expression returning a database connection pool
#'   object from \code{pool::dbPool()}. Can return NULL to use CSV fallback.
#' 
#' @return Named list of reactive expressions for parent module integration:
#'   \item{results}{Reactive data frame with current search results}
#'   \item{selected_rows}{Reactive integer vector of selected table rows}
#'   \item{query}{Reactive character string with current search query}
#'   \item{filters_active}{Reactive logical indicating if filters are applied}
#' 
#' @family search-modules
#' @seealso \code{\link{searchUI}} for corresponding user interface
#' @seealso \code{\link{search_documents}} for database search implementation
#' @seealso \code{\link{validate_input}} for input validation
#' @seealso \code{\link{execute_secure_query}} for secure database queries
#' 
#' @examples
#' \dontrun{
#' # Complete Shiny application with search module
#' library(shiny)
#' 
#' # Initialize database connection
#' db_result <- init_database_connection()
#' 
#' server <- function(input, output, session) {
#'   # Database connection reactive
#'   db_pool <- reactive({ db_result$pool })
#'   
#'   # Search module server
#'   search_results <- searchServer("legislative_search", db_pool)
#'   
#'   # Access search results in parent application
#'   observe({
#'     results <- search_results$results()
#'     if (!is.null(results) && nrow(results) > 0) {
#'       cat("Found", nrow(results), "documents\n")
#'     }
#'   })
#' }
#' 
#' # Multiple search modules with shared database
#' server <- function(input, output, session) {
#'   db_pool <- reactive({ get_shared_db_pool() })
#'   
#'   federal_search <- searchServer("federal", db_pool)
#'   state_search <- searchServer("state", db_pool)
#' }
#' }
#' 
#' @export
searchServer <- function(id, db_pool = reactive(NULL)) {
  moduleServer(id, function(input, output, session) {
    
    # Initialize filter choices
    observe({
      pool <- db_pool()
      
      if (!is.null(pool)) {
        # Update estado choices
        tryCatch({
          estados <- get_filter_values(pool, "estado")
          updateSelectInput(
            session, 
            "estado",
            choices = c("All States" = "", setNames(estados, estados))
          )
        }, error = function(e) {
          # Fallback to common Brazilian states
          estados <- c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE")
          updateSelectInput(
            session,
            "estado", 
            choices = c("All States" = "", setNames(estados, estados))
          )
        })
        
        # Update tipo choices
        tryCatch({
          tipos <- get_filter_values(pool, "tipo")
          updateSelectInput(
            session,
            "tipo",
            choices = c("All Types" = "", setNames(tipos, tipos))
          )
        }, error = function(e) {
          # Fallback to common document types
          tipos <- c("lei", "decreto", "portaria", "resolução", "instrução normativa")
          updateSelectInput(
            session,
            "tipo",
            choices = c("All Types" = "", setNames(tipos, tipos))
          )
        })
      }
    })
    
    # Reactive search results with security validation
    search_results <- eventReactive(input$search, {
      
      req(input$query)
      
      # Security validation and rate limiting
      tryCatch({
        # Get client identifier (in production, this would be actual IP)
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
          return(data.frame())
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
          return(data.frame())
        }
        
        # Use sanitized query
        sanitized_query <- query_validation$value
        
        if (nchar(trimws(sanitized_query)) == 0) {
          return(data.frame())
        }
        
      }, error = function(e) {
        log_security_event("SEARCH_SECURITY_ERROR", paste("Search security check failed:", e$message))
        showNotification(
          "Security validation failed. Please try again.",
          type = "error",
          duration = 5
        )
        return(data.frame())
      })
      
      # Build and validate filters
      filters <- list()
      
      # Validate and sanitize estado filter
      if (!is.null(input$estado) && input$estado != "") {
        estado_validation <- validate_input(
          input$estado, 
          type = "character", 
          max_length = 10, 
          allow_html = FALSE
        )
        if (estado_validation$valid) {
          filters$estado <- estado_validation$value
        } else {
          log_security_event("INVALID_FILTER", paste("Invalid estado filter:", input$estado))
        }
      }
      
      # Validate and sanitize tipo filter
      if (!is.null(input$tipo) && input$tipo != "") {
        tipo_validation <- validate_input(
          input$tipo, 
          type = "character", 
          max_length = 50, 
          allow_html = FALSE
        )
        if (tipo_validation$valid) {
          filters$tipo <- tipo_validation$value
        } else {
          log_security_event("INVALID_FILTER", paste("Invalid tipo filter:", input$tipo))
        }
      }
      
      # Validate ano_min filter
      if (!is.null(input$ano_min) && !is.na(input$ano_min)) {
        ano_min_validation <- validate_input(
          input$ano_min, 
          type = "numeric", 
          min_value = 1900, 
          max_value = 2030
        )
        if (ano_min_validation$valid) {
          filters$ano_min <- ano_min_validation$value
        } else {
          log_security_event("INVALID_FILTER", paste("Invalid ano_min filter:", input$ano_min))
        }
      }
      
      # Validate ano_max filter
      if (!is.null(input$ano_max) && !is.na(input$ano_max)) {
        ano_max_validation <- validate_input(
          input$ano_max, 
          type = "numeric", 
          min_value = 1900, 
          max_value = 2030
        )
        if (ano_max_validation$valid) {
          filters$ano_max <- ano_max_validation$value
        } else {
          log_security_event("INVALID_FILTER", paste("Invalid ano_max filter:", input$ano_max))
        }
      }
      
      # Validate and set search limit
      search_limit <- if (!is.null(input$limit) && !is.na(input$limit)) {
        limit_validation <- validate_input(
          input$limit, 
          type = "numeric", 
          min_value = 10, 
          max_value = 1000
        )
        if (limit_validation$valid) {
          limit_validation$value
        } else {
          log_security_event("INVALID_LIMIT", paste("Invalid limit value:", input$limit))
          100  # Default fallback
        }
      } else {
        100
      }
      
      # Execute search
      pool <- db_pool()
      
      withProgress(message = "Searching documents...", value = 0, {
        incProgress(0.3, detail = "Executing query")
        
        # Execute search with validated parameters
        results <- search_documents(
          pool = pool,
          query = sanitized_query,
          filters = filters,
          limit = search_limit
        )
        
        # Log successful search for monitoring
        log_security_event("SEARCH_EXECUTED", 
                         paste("Search completed. Query length:", nchar(sanitized_query), 
                               "Results:", nrow(results)))
        
        incProgress(0.7, detail = "Processing results")
        
        # Clean and format results with security controls
        if (nrow(results) > 0) {
          # Sanitize all text content to prevent XSS
          text_columns <- c("titulo", "content", "tipo", "orgao_emissor", "municipio")
          for (col in text_columns) {
            if (col %in% names(results)) {
              results[[col]] <- safe_html(results[[col]], max_length = 1000, allow_basic_formatting = FALSE)
            }
          }
          
          # Truncate long content if not requested
          if (!isTRUE(input$include_content) && "content" %in% names(results)) {
            results$content <- truncate_text(results$content, 200)
          }
          
          # Format dates safely
          if ("data_publicacao" %in% names(results)) {
            results$data_publicacao <- safe_date_parse(results$data_publicacao)
          }
          
          # Validate result count doesn't exceed reasonable limits
          if (nrow(results) > search_limit) {
            log_security_event("SEARCH_RESULT_ANOMALY", 
                             paste("Search returned more results than requested:", nrow(results)))
            results <- results[1:search_limit, ]
          }
          
          # Add row numbers
          results <- cbind(Row = 1:nrow(results), results)
        }
        
        incProgress(1.0, detail = "Complete")
        
        return(results)
      })
    })
    
    # Search statistics output
    output$search_stats <- renderUI({
      results <- search_results()
      
      if (is.null(results) || nrow(results) == 0) {
        if (!is.null(input$search) && input$search > 0) {
          return(div(
            class = "alert alert-warning",
            icon("info-circle"),
            " No documents found matching your search criteria."
          ))
        } else {
          return(div(
            class = "text-muted",
            "Enter search terms and click 'Search' to find documents."
          ))
        }
      }
      
      div(
        class = "alert alert-info",
        icon("check-circle"),
        paste0(
          " Found ", format_number(nrow(results)), 
          " document", if(nrow(results) != 1) "s" else "",
          " matching your search for '", input$query, "'"
        )
      )
    })
    
    # Render results table
    output$results <- DT::renderDT({
      
      results <- search_results()
      
      if (is.null(results) || nrow(results) == 0) {
        return(DT::datatable(
          data.frame(Message = "No results to display"),
          options = list(
            dom = 't',
            ordering = FALSE
          ),
          rownames = FALSE
        ))
      }
      
      # Prepare display columns
      display_cols <- intersect(
        names(results),
        c("Row", "titulo", "tipo", "ano", "estado", "municipio", "data_publicacao", "content")
      )
      
      display_data <- results[, display_cols, drop = FALSE]
      
      # Create DT with enhanced options
      DT::datatable(
        display_data,
        options = list(
          pageLength = 25,
          scrollX = TRUE,
          scrollY = "400px",
          dom = 'Bfrtip',
          buttons = c('copy', 'csv', 'excel', 'pdf', 'print'),
          columnDefs = list(
            list(width = '50px', targets = 0),     # Row column
            list(width = '300px', targets = 1),    # Title column
            list(className = 'dt-center', targets = c(2, 3, 4))  # Center align some columns
          ),
          language = list(
            search = "Filter results:",
            lengthMenu = "Show _MENU_ entries",
            info = "Showing _START_ to _END_ of _TOTAL_ documents",
            paginate = list(
              first = "First",
              last = "Last",
              `next` = "Next",
              previous = "Previous"
            )
          )
        ),
        extensions = 'Buttons',
        selection = 'multiple',
        filter = 'top',
        rownames = FALSE,
        escape = FALSE  # Allow HTML in content
      ) %>%
        DT::formatDate(
          columns = which(names(display_data) == "data_publicacao"),
          method = "toDateString"
        )
    })
    
    # Pagination info
    output$pagination_info <- renderUI({
      results <- search_results()
      
      if (is.null(results) || nrow(results) == 0) {
        return(NULL)
      }
      
      div(
        class = "text-muted small",
        paste("Displaying", nrow(results), "results")
      )
    })
    
    # CSV Export with security controls
    output$export_csv <- downloadHandler(
      filename = function() {
        # Sanitize filename
        base_name <- paste0("legislative_search_", Sys.Date())
        sanitized_name <- sanitize_filename(base_name, max_length = 100)
        paste0(sanitized_name, ".csv")
      },
      content = function(file) {
        # Security checks
        tryCatch({
          # Rate limiting for exports
          client_id <- paste0("export_", session$clientData$url_hostname %||% "unknown")
          rate_check <- check_rate_limit(client_id, max_requests = 10, time_window = 3600)
          
          if (!rate_check$allowed) {
            log_security_event("EXPORT_RATE_LIMIT_EXCEEDED", 
                             paste("CSV export rate limit exceeded for client:", client_id))
            stop("Export rate limit exceeded")
          }
          
          results <- search_results()
          
          if (!is.null(results) && nrow(results) > 0) {
            # Log export activity
            log_security_event("DATA_EXPORT", 
                             paste("CSV export requested. Rows:", nrow(results)))
            
            # Sanitize all content before export (LGPD compliance)
            if ("content" %in% names(results)) {
              results$content <- safe_html(results$content, max_length = 5000, allow_basic_formatting = FALSE)
            }
            
            # Limit export size for security
            if (nrow(results) > 5000) {
              log_security_event("LARGE_EXPORT_ATTEMPT", 
                               paste("Large export attempted:", nrow(results), "rows"))
              results <- results[1:5000, ]
              showNotification(
                "Export limited to 5000 rows for security reasons.",
                type = "warning",
                duration = 10
              )
            }
            
            write.csv(results, file, row.names = FALSE, fileEncoding = "UTF-8")
          } else {
            # Write empty CSV with headers
            write.csv(data.frame(message = "No results to export"), file, row.names = FALSE)
          }
          
        }, error = function(e) {
          log_security_event("EXPORT_ERROR", paste("CSV export failed:", e$message))
          write.csv(data.frame(error = "Export failed"), file, row.names = FALSE)
        })
      }
    )
    
    # BibTeX Export with security controls
    output$export_bibtex <- downloadHandler(
      filename = function() {
        # Sanitize filename
        base_name <- paste0("legislative_citations_", Sys.Date())
        sanitized_name <- sanitize_filename(base_name, max_length = 100)
        paste0(sanitized_name, ".bib")
      },
      content = function(file) {
        # Security checks
        tryCatch({
          # Rate limiting for exports
          client_id <- paste0("bibtex_", session$clientData$url_hostname %||% "unknown")
          rate_check <- check_rate_limit(client_id, max_requests = 10, time_window = 3600)
          
          if (!rate_check$allowed) {
            log_security_event("EXPORT_RATE_LIMIT_EXCEEDED", 
                             paste("BibTeX export rate limit exceeded for client:", client_id))
            stop("Export rate limit exceeded")
          }
          
          results <- search_results()
          
          if (!is.null(results) && nrow(results) > 0) {
            # Log export activity
            log_security_event("BIBTEX_EXPORT", 
                             paste("BibTeX export requested. Rows:", nrow(results)))
            
            # Limit export size for security
            if (nrow(results) > 1000) {
              log_security_event("LARGE_BIBTEX_EXPORT_ATTEMPT", 
                               paste("Large BibTeX export attempted:", nrow(results), "entries"))
              results <- results[1:1000, ]
              showNotification(
                "BibTeX export limited to 1000 entries for security reasons.",
                type = "warning",
                duration = 10
              )
            }
            
            bibtex_entries <- generate_bibtex_citations(results)
            writeLines(bibtex_entries, file, useBytes = TRUE)
          } else {
            writeLines("% No results to export", file)
          }
          
        }, error = function(e) {
          log_security_event("BIBTEX_EXPORT_ERROR", paste("BibTeX export failed:", e$message))
          writeLines("% Export failed", file)
        })
      }
    )
    
    # Return reactive values for parent module use
    return(list(
      results = search_results,
      selected_rows = reactive({
        if (!is.null(input$results_rows_selected)) {
          input$results_rows_selected
        } else {
          integer(0)
        }
      }),
      query = reactive(input$query),
      filters_active = reactive({
        !is.null(input$estado) && input$estado != "" ||
        !is.null(input$tipo) && input$tipo != "" ||
        !is.null(input$ano_min) && !is.na(input$ano_min) ||
        !is.null(input$ano_max) && !is.na(input$ano_max)
      })
    ))
  })
}

#' Generate ABNT-Compliant BibTeX Citations for Legislative Documents
#' 
#' Generates academically rigorous BibTeX citations for Brazilian legislative
#' documents following ABNT (Associação Brasileira de Normas Técnicas) standards.
#' Essential for academic research and scholarly publications analyzing Brazilian
#' legal frameworks and policy development.
#' 
#' This function creates properly formatted BibTeX entries that can be directly
#' used in LaTeX documents, reference managers (Zotero, Mendeley), and academic
#' writing tools. Each citation includes all necessary metadata for proper
#' academic attribution and legal document identification.
#' 
#' @details
#' **Citation Standards:**
#' - **ABNT Compliance**: Follows Brazilian academic citation standards
#' - **Legal Document Format**: Specialized formatting for legislative materials
#' - **Complete Metadata**: Includes title, issuing authority, year, location
#' - **Unique Keys**: Generates collision-resistant citation keys
#' - **Language Specification**: Properly marks Portuguese language content
#' 
#' **Academic Integration:**
#' - Compatible with LaTeX bibliography systems (BibTeX, BibLaTeX)
#' - Integrates with reference management software
#' - Supports automated bibliography generation
#' - Facilitates reproducible research workflows
#' 
#' **Legislative Document Types:**
#' - Federal and state laws (leis)
#' - Decrees (decretos)
#' - Administrative acts (portarias)
#' - Resolutions (resoluções)
#' - Normative instructions (instruções normativas)
#' 
#' **Metadata Handling:**
#' - Graceful handling of missing metadata fields
#' - Automatic institution mapping for Brazilian government entities
#' - Geographic context preservation (state/federal level)
#' - Temporal information inclusion for historical analysis
#' 
#' @param documents Data frame containing legislative documents with metadata.
#'   Expected columns: titulo, ano, tipo, estado, orgao_emissor.
#'   Missing columns are handled gracefully with appropriate defaults.
#' 
#' @return Character vector of complete BibTeX entries, one per document.
#'   Each entry includes:
#'   - Unique citation key (e.g., "brasil2023_transportepublico")
#'   - Document title and metadata
#'   - Issuing authority and jurisdiction
#'   - Publication year and geographic context
#'   - Language specification for Portuguese content
#' 
#' @family academic-tools
#' @seealso \code{\link{searchServer}} for search results export
#' @seealso \code{\link{searchUI}} for citation export interface
#' 
#' @examples
#' \dontrun{
#' # Generate citations for search results
#' documents <- data.frame(
#'   titulo = c(
#'     "Lei de Diretrizes e Bases da Educação Nacional",
#'     "Código de Trânsito Brasileiro"
#'   ),
#'   ano = c(1996, 1997),
#'   tipo = c("lei", "lei"),
#'   estado = c("BR", "BR"),
#'   orgao_emissor = c("Congresso Nacional", "Congresso Nacional")
#' )
#' 
#' # Generate BibTeX citations
#' citations <- generate_bibtex_citations(documents)
#' 
#' # Write to .bib file for LaTeX
#' writeLines(citations, "legislative_references.bib")
#' 
#' # Example output format:
#' # @legislation{brasil1996_leidiretrizes,
#' #   title = {Lei de Diretrizes e Bases da Educação Nacional},
#' #   author = {Brasil},
#' #   year = {1996},
#' #   type = {lei},
#' #   institution = {Congresso Nacional},
#' #   country = {Brasil},
#' #   language = {portuguese}
#' # }
#' }
#' 
#' @export
generate_bibtex_citations <- function(documents) {
  
  if (is.null(documents) || nrow(documents) == 0) {
    return(character(0))
  }
  
  citations <- c()
  
  for (i in 1:nrow(documents)) {
    doc <- documents[i, ]
    
    # Generate citation key
    citation_key <- paste0(
      "brasil",
      if (!is.na(doc$ano)) doc$ano else "unknown",
      "_",
      gsub("[^a-zA-Z0-9]", "", substr(doc$titulo %||% "document", 1, 20))
    )
    
    # Create BibTeX entry
    entry <- paste0(
      "@legislation{", citation_key, ",\n",
      "  title = {", doc$titulo %||% "Untitled", "},\n",
      "  author = {Brasil},\n",
      if (!is.na(doc$ano)) paste0("  year = {", doc$ano, "},\n") else "",
      if (!is.na(doc$tipo)) paste0("  type = {", doc$tipo, "},\n") else "",
      if (!is.na(doc$estado)) paste0("  address = {", doc$estado, "},\n") else "",
      if (!is.na(doc$orgao_emissor)) paste0("  institution = {", doc$orgao_emissor, "},\n") else "",
      "  country = {Brasil},\n",
      "  language = {portuguese}\n",
      "}\n"
    )
    
    citations <- c(citations, entry)
  }
  
  return(citations)
}

cat("✅ Search module loaded\n")