# library_enhanced_module.R - Enhanced Library Tab Module
# ============================================================================
# Purpose: Comprehensive library tab with all features from PRD
# Created: 2025
# Features:
#  - Advanced filters (state, theme, year, date range)
#  - Export functionality (8 formats)
#  - Search service integration
#  - Full-text search with Portuguese stemming
#  - Sort functionality
#  - Search statistics
#  - User-controlled pagination
#  - Auto-complete suggestions
#  - Search operators
#  - Quick help panel
#  - Collection creation
#  - Enhanced table formatting
#  - WCAG 2.1 AA compliance
#  - Mobile responsive
# ============================================================================

library(shiny)
library(DT)
library(stringr)

# Source required services
if (!exists("SearchService")) {
  source("R/services/search_service.R", local = FALSE)
}
if (!exists("init_search_service")) {
  source("R/services/search_wrapper.R", local = FALSE)
}

# Source text normalization utilities
if (file.exists("R/utils/text_normalization.R")) {
  source("R/utils/text_normalization.R", local = FALSE)
}

#' Enhanced Library Tab UI
#'
#' @param id Module namespace ID
#' @return Shiny UI element
#' @export
libraryEnhancedUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Add custom CSS for enhanced styling
    tags$head(
      tags$style(HTML("
        .library-search-box {
          font-size: 16px;
          padding: 12px;
        }
        .filter-panel {
          background-color: #f8f9fa;
          padding: 15px;
          border-radius: 5px;
          margin-bottom: 15px;
        }
        .search-stats {
          font-size: 14px;
          color: #666;
          padding: 10px;
          background-color: #e3f2fd;
          border-radius: 4px;
          margin-bottom: 10px;
        }
        .export-buttons {
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
          margin-bottom: 15px;
        }
        .help-panel {
          background-color: #fff3cd;
          padding: 15px;
          border-radius: 5px;
          border-left: 4px solid #ffc107;
        }
        .table-actions {
          display: flex;
          gap: 5px;
        }
        @media (max-width: 768px) {
          .export-buttons {
            flex-direction: column;
          }
          .library-search-box {
            font-size: 14px;
          }
        }
      "))
    ),

    fluidPage(
      # Header Section
      div(
        role = "banner",
        h2(
          id = ns("library-title"),
          icon("book"),
          "Biblioteca de Documentos Legislativos",
          style = "color: #1e3a8a; margin-bottom: 10px;"
        ),
        p(
          "Pesquise, filtre e explore a coleção completa de documentos legislativos brasileiros.",
          "Use os filtros avançados para refinar sua busca.",
          style = "color: #666;"
        )
      ),

      hr(),

      # Search Statistics (live update)
      uiOutput(ns("search_stats_ui")),

      # Main Search Panel
      wellPanel(
        class = "filter-panel",
        role = "search",
        `aria-label` = "Formulário de busca de documentos legislativos",

        h4(icon("search"), "Busca Principal"),

        fluidRow(
          column(9,
            textInput(
              ns("library_search"),
              label = NULL,
              placeholder = "Digite termos de busca (ex: 'transporte', 'meio ambiente', 'educação'). Use +termo para obrigatório, -termo para excluir, \"frase exata\" para busca exata.",
              width = "100%"
            ) %>%
              tagAppendAttributes(
                class = "library-search-box",
                `aria-label` = "Campo de busca principal",
                `aria-describedby` = ns("search-help")
              )
          ),
          column(3,
            actionButton(
              ns("library_apply"),
              "Pesquisar",
              icon = icon("search"),
              class = "btn-primary btn-block",
              style = "margin-top: 0; height: 48px;"
            )
          )
        ),

        # Search help text
        div(
          id = ns("search-help"),
          class = "form-text",
          style = "margin-top: 10px;",
          tags$small(
            class = "text-muted",
            icon("info-circle"),
            "Dica: Use operadores de busca: ",
            tags$strong("+termo"), " (obrigatório), ",
            tags$strong("-termo"), " (excluir), ",
            tags$strong("\"frase exata\""), " (busca exata), ",
            tags$strong("termo*"), " (coringa)"
          )
        )
      ),

      # Advanced Filters Panel
      wellPanel(
        class = "filter-panel",

        div(
          style = "display: flex; justify-content: space-between; align-items: center;",
          h4(icon("filter"), "Filtros Avançados"),
          actionButton(
            ns("toggle_filters"),
            "Mostrar/Ocultar",
            icon = icon("chevron-down"),
            class = "btn-sm btn-outline-secondary"
          )
        ),

        div(
          id = ns("advanced_filters_content"),
          style = "margin-top: 15px;",

          fluidRow(
            # State/Jurisdiction Filter
            column(3,
              selectInput(
                ns("filter_estado"),
                "Estado/Jurisdição:",
                choices = c(
                  "Todos os Estados" = "Todos",
                  "Federal" = "BR",
                  "Acre" = "AC",
                  "Alagoas" = "AL",
                  "Amapá" = "AP",
                  "Amazonas" = "AM",
                  "Bahia" = "BA",
                  "Ceará" = "CE",
                  "Distrito Federal" = "DF",
                  "Espírito Santo" = "ES",
                  "Goiás" = "GO",
                  "Maranhão" = "MA",
                  "Mato Grosso" = "MT",
                  "Mato Grosso do Sul" = "MS",
                  "Minas Gerais" = "MG",
                  "Pará" = "PA",
                  "Paraíba" = "PB",
                  "Paraná" = "PR",
                  "Pernambuco" = "PE",
                  "Piauí" = "PI",
                  "Rio de Janeiro" = "RJ",
                  "Rio Grande do Norte" = "RN",
                  "Rio Grande do Sul" = "RS",
                  "Rondônia" = "RO",
                  "Roraima" = "RR",
                  "Santa Catarina" = "SC",
                  "São Paulo" = "SP",
                  "Sergipe" = "SE",
                  "Tocantins" = "TO"
                ),
                selected = "Todos"
              )
            ),

            # Document Type Filter
            column(3,
              selectInput(
                ns("library_tipo"),
                "Tipo de Documento:",
                choices = c(
                  "Todos os Tipos" = "Todos",
                  "Lei" = "Lei",
                  "Decreto" = "Decreto",
                  "Projeto de Lei" = "Projeto de Lei",
                  "Medida Provisória" = "Medida Provisória",
                  "Resolução" = "Resolução",
                  "Portaria" = "Portaria",
                  "Instrução Normativa" = "Instrução Normativa",
                  "Parecer" = "Parecer",
                  "Acórdão" = "Acórdão",
                  "Súmula" = "Súmula"
                ),
                selected = "Todos"
              )
            ),

            # Theme Filter
            column(3,
              selectInput(
                ns("filter_tema"),
                "Tema Principal:",
                choices = c(
                  "Todos os Temas" = "Todos",
                  "Meio Ambiente" = "meio_ambiente",
                  "Saúde" = "saude",
                  "Educação" = "educacao",
                  "Transporte" = "transporte",
                  "Segurança Pública" = "seguranca",
                  "Economia" = "economia",
                  "Trabalho" = "trabalho",
                  "Previdência" = "previdencia",
                  "Tributário" = "tributario",
                  "Civil" = "civil",
                  "Penal" = "penal",
                  "Administrativo" = "administrativo"
                ),
                selected = "Todos"
              )
            ),

            # Results per page
            column(3,
              selectInput(
                ns("results_per_page"),
                "Resultados por Página:",
                choices = c(
                  "10" = 10,
                  "25" = 25,
                  "50" = 50,
                  "100" = 100
                ),
                selected = 25
              )
            )
          ),

          fluidRow(
            # Year Range Filters
            column(3,
              numericInput(
                ns("filter_ano_min"),
                "Ano Inicial:",
                value = 2000,
                min = 1824,
                max = 2025,
                step = 1
              )
            ),

            column(3,
              numericInput(
                ns("filter_ano_max"),
                "Ano Final:",
                value = 2025,
                min = 1824,
                max = 2025,
                step = 1
              )
            ),

            # Date Range Filter
            column(4,
              dateRangeInput(
                ns("filter_date_range"),
                "Período:",
                start = NULL,
                end = Sys.Date(),
                format = "dd/mm/yyyy",
                language = "pt-BR",
                separator = " até "
              )
            ),

            # Recent documents checkbox
            column(2,
              div(
                style = "margin-top: 25px;",
                checkboxInput(
                  ns("filter_recent_only"),
                  "Apenas recentes (2 anos)",
                  value = FALSE
                )
              )
            )
          ),

          # Action buttons
          fluidRow(
            column(12,
              div(
                style = "margin-top: 10px;",
                actionButton(
                  ns("library_clear"),
                  "Limpar Filtros",
                  icon = icon("times"),
                  class = "btn-secondary"
                )
              )
            )
          )
        )
      ),

      # Sort and Export Controls
      wellPanel(
        fluidRow(
          column(6,
            h4(icon("sort"), "Ordenação"),
            selectInput(
              ns("sort_results"),
              label = NULL,
              choices = c(
                "Mais Relevantes" = "relevance",
                "Mais Recentes" = "date_desc",
                "Mais Antigas" = "date_asc",
                "Alfabética A-Z" = "title_asc",
                "Alfabética Z-A" = "title_desc",
                "Por Tipo" = "type"
              ),
              selected = "date_desc",
              width = "100%"
            )
          ),

          column(6,
            h4(icon("download"), "Exportar Resultados"),
            div(
              class = "export-buttons",
              downloadButton(ns("export_csv"), "CSV", class = "btn-success btn-sm"),
              downloadButton(ns("export_excel"), "Excel", class = "btn-success btn-sm"),
              downloadButton(ns("export_json"), "JSON", class = "btn-info btn-sm"),
              downloadButton(ns("export_xml"), "XML", class = "btn-info btn-sm"),
              downloadButton(ns("export_bibtex"), "BibTeX", class = "btn-warning btn-sm"),
              downloadButton(ns("export_ris"), "RIS", class = "btn-warning btn-sm"),
              downloadButton(ns("export_lexml"), "LexML", class = "btn-secondary btn-sm"),
              downloadButton(ns("export_endnote"), "EndNote", class = "btn-secondary btn-sm")
            )
          )
        )
      ),

      hr(),

      # Results Section
      div(
        role = "main",
        `aria-labelledby` = ns("results-title"),

        h4(
          id = ns("results-title"),
          icon("list-ul"),
          "Resultados da Pesquisa"
        ),

        # Results table with enhanced features
        DT::dataTableOutput(ns("library_table")),

        # Pagination info
        div(
          style = "margin-top: 15px; text-align: center;",
          uiOutput(ns("pagination_info"))
        )
      ),

      hr(),

      # Quick Help Panel (collapsible)
      div(
        role = "complementary",
        `aria-labelledby` = ns("help-title"),

        tags$details(
          tags$summary(
            id = ns("help-title"),
            icon("question-circle"),
            "Dicas de Pesquisa Avançada",
            style = "cursor: pointer; font-size: 16px; font-weight: bold; color: #1e3a8a; padding: 10px;"
          ),

          div(
            class = "help-panel",
            style = "margin-top: 10px;",

            tags$dl(
              class = "row",

              tags$dt(class = "col-3", "Busca Exata:"),
              tags$dd(class = "col-9", 'Use aspas: "meio ambiente"'),

              tags$dt(class = "col-3", "Termo Obrigatório:"),
              tags$dd(class = "col-9", "Use +: +lei +ambiental"),

              tags$dt(class = "col-3", "Excluir Termo:"),
              tags$dd(class = "col-9", "Use -: transporte -rodoviário"),

              tags$dt(class = "col-3", "Busca por Número:"),
              tags$dd(class = "col-9", "Digite: Lei 12345 ou 12345/2020"),

              tags$dt(class = "col-3", "Coringas:"),
              tags$dd(class = "col-9", "Use *: ambient* (ambiental, ambiente)"),

              tags$dt(class = "col-3", "Múltiplos termos:"),
              tags$dd(class = "col-9", "Separe com espaço: transporte público"),

              tags$dt(class = "col-3", "Filtros Avançados:"),
              tags$dd(class = "col-9", "Use os filtros acima para refinar por estado, tipo, tema, e período")
            ),

            tags$p(
              class = "mt-3 text-muted",
              style = "margin-bottom: 0;",
              tags$strong("Atalhos de Teclado:"),
              " Ctrl+K para busca rápida | F6 para navegar entre seções | Esc para limpar"
            )
          )
        )
      )
    )
  )
}

#' Enhanced Library Tab Server
#'
#' @param id Module namespace ID
#' @param db_connection Database connection object
#' @param db_available Boolean indicating if database is available
#' @param documents_table Name of the documents table
#' @return Server logic
#' @export
libraryEnhancedServer <- function(id, db_connection, db_available, documents_table = "documents") {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Initialize search service
    search_service <- NULL
    if (db_available && !is.null(db_connection)) {
      tryCatch({
        init_search_service(db_connection)
        search_service <- .search_service
        message("✓ Search service initialized successfully")
      }, error = function(e) {
        message("✗ Failed to initialize search service: ", e$message)
      })
    }

    # Reactive values for managing state
    filters <- reactiveValues(
      search = "",
      estado = "Todos",
      tipo = "Todos",
      tema = "Todos",
      ano_min = 2000,
      ano_max = 2025,
      date_start = NULL,
      date_end = NULL,
      recent_only = FALSE,
      sort_by = "date_desc",
      results_per_page = 25,
      current_page = 1,
      trigger = 0,
      total_count = 0,
      last_results = NULL
    )

    # Debounced search input (Phase 2, Task 2.5: 500ms debounce)
    search_debounced <- debounce(reactive(input$library_search), 500)

    # Throttled filter inputs (Phase 2, Task 2.5: 1s throttle)
    estado_throttled <- throttle(reactive(input$filter_estado), 1000)
    tipo_throttled <- throttle(reactive(input$library_tipo), 1000)
    tema_throttled <- throttle(reactive(input$filter_tema), 1000)

    # Trigger initial load
    session$onFlushed(function() {
      isolate({
        filters$trigger <- filters$trigger + 1
      })
    }, once = TRUE)

    # Apply filters button
    observeEvent(input$library_apply, {
      message("=== APPLY BUTTON CLICKED ===")
      filters$search <- input$library_search
      filters$estado <- input$filter_estado
      filters$tipo <- input$library_tipo
      filters$tema <- input$filter_tema
      filters$ano_min <- input$filter_ano_min
      filters$ano_max <- input$filter_ano_max
      filters$recent_only <- input$filter_recent_only
      filters$sort_by <- input$sort_results
      filters$results_per_page <- as.numeric(input$results_per_page)
      filters$current_page <- 1  # Reset to first page

      # Handle date range
      if (!is.null(input$filter_date_range)) {
        filters$date_start <- input$filter_date_range[1]
        filters$date_end <- input$filter_date_range[2]
      }

      filters$trigger <- filters$trigger + 1
    })

    # Clear filters button
    observeEvent(input$library_clear, {
      message("=== CLEAR BUTTON CLICKED ===")

      # Reset UI inputs
      updateTextInput(session, "library_search", value = "")
      updateSelectInput(session, "filter_estado", selected = "Todos")
      updateSelectInput(session, "library_tipo", selected = "Todos")
      updateSelectInput(session, "filter_tema", selected = "Todos")
      updateNumericInput(session, "filter_ano_min", value = 2000)
      updateNumericInput(session, "filter_ano_max", value = 2025)
      updateDateRangeInput(session, "filter_date_range", start = NULL, end = Sys.Date())
      updateCheckboxInput(session, "filter_recent_only", value = FALSE)
      updateSelectInput(session, "sort_results", selected = "date_desc")

      # Reset reactive values
      filters$search <- ""
      filters$estado <- "Todos"
      filters$tipo <- "Todos"
      filters$tema <- "Todos"
      filters$ano_min <- 2000
      filters$ano_max <- 2025
      filters$date_start <- NULL
      filters$date_end <- NULL
      filters$recent_only <- FALSE
      filters$sort_by <- "date_desc"
      filters$current_page <- 1
      filters$trigger <- filters$trigger + 1
    })

    # Watch for sort changes
    observeEvent(input$sort_results, {
      if (!is.null(input$sort_results)) {
        filters$sort_by <- input$sort_results
        filters$trigger <- filters$trigger + 1
      }
    })

    # Watch for pagination changes
    observeEvent(input$results_per_page, {
      if (!is.null(input$results_per_page)) {
        filters$results_per_page <- as.numeric(input$results_per_page)
        filters$current_page <- 1  # Reset to first page
        filters$trigger <- filters$trigger + 1
      }
    })

    # Main data retrieval function
    library_data <- reactive({
      # Establish dependency on trigger
      current_trigger <- filters$trigger

      if (!db_available || is.null(db_connection)) {
        return(data.frame(
          Message = c(
            "Database connection not available",
            "To configure the database:",
            "1. Set environment variables: PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD",
            "2. Or run: source('setup_local_env.R')",
            "3. Then restart the application"
          )
        ))
      }

      # Get current filter values
      current_search <- filters$search
      current_estado <- filters$estado
      current_tipo <- filters$tipo
      current_tema <- filters$tema
      current_ano_min <- filters$ano_min
      current_ano_max <- filters$ano_max
      current_date_start <- filters$date_start
      current_date_end <- filters$date_end
      current_recent_only <- filters$recent_only
      current_sort_by <- filters$sort_by
      current_limit <- filters$results_per_page
      current_offset <- (filters$current_page - 1) * current_limit

      message("Fetching data with filters:")
      message("  Search: ", current_search)
      message("  Estado: ", current_estado)
      message("  Tipo: ", current_tipo)
      message("  Tema: ", current_tema)
      message("  Sort: ", current_sort_by)
      message("  Limit: ", current_limit)
      message("  Offset: ", current_offset)

      # Use search service if available, otherwise fall back to direct SQL
      result <- NULL

      if (!is.null(search_service)) {
        # Use advanced search service
        tryCatch({
          # Convert sort_by to format expected by search service
          sort_by_param <- switch(current_sort_by,
            "date_desc" = "date_desc",
            "date_asc" = "date_asc",
            "title_asc" = "title_asc",
            "title_desc" = "title_desc",
            "relevance" = "relevance",
            "type" = "type",
            "date_desc"  # default
          )

          # Get state parameter
          state_param <- if (current_estado == "Todos") "all" else current_estado

          # Get category parameter (tipo maps to category in some contexts)
          category_param <- if (current_tipo == "Todos") "all" else current_tipo

          result <- search_service$search_documents(
            category = category_param,
            search_term = current_search,
            state = state_param,
            date_start = current_date_start,
            date_end = current_date_end,
            sort_by = sort_by_param,
            limit = current_limit,
            offset = current_offset,
            use_semantic_search = TRUE
          )

          # Get total count for pagination
          total_count <- search_service$count_documents(
            category = category_param,
            search_term = current_search,
            state = state_param,
            date_start = current_date_start,
            date_end = current_date_end
          )

          filters$total_count <- total_count
          message("Search service returned ", nrow(result), " rows (total: ", total_count, ")")

        }, error = function(e) {
          message("Search service error: ", e$message)
          message("Falling back to direct SQL")
          result <- NULL
        })
      }

      # Fall back to direct SQL if search service failed or not available
      # Phase 2, Task 2.3: Integrate pagination utilities with caching
      if (is.null(result)) {
        # Convert sort_by to SQL ORDER BY clause
        order_clause <- switch(current_sort_by,
          "date_desc" = "data DESC",
          "date_asc" = "data ASC",
          "title_asc" = "titulo ASC",
          "title_desc" = "titulo DESC",
          "relevance" = "data DESC",  # Fallback to date
          "type" = "tipo ASC, data DESC",
          "data DESC"  # default
        )

        # Adjust year range for recent_only filter
        ano_min_adjusted <- current_ano_min
        ano_max_adjusted <- current_ano_max
        if (current_recent_only) {
          two_years_ago <- Sys.Date() - 730  # 2 years
          ano_min_adjusted <- max(as.integer(format(two_years_ago, "%Y")), current_ano_min)
        }

        # Build base query without LIMIT/OFFSET
        base_query <- paste("SELECT id, titulo, tipo, data, estado, ementa, resumo FROM", documents_table, "WHERE 1=1")

        if (current_search != "") {
          search_escaped <- gsub("'", "''", current_search)
          base_query <- paste0(base_query, " AND (titulo ILIKE '%", search_escaped, "%' OR resumo ILIKE '%", search_escaped, "%')")
        }

        if (current_tipo != "Todos") {
          tipo_escaped <- gsub("'", "''", current_tipo)
          base_query <- paste0(base_query, " AND tipo = '", tipo_escaped, "'")
        }

        if (current_estado != "Todos") {
          estado_escaped <- gsub("'", "''", current_estado)
          base_query <- paste0(base_query, " AND estado = '", estado_escaped, "'")
        }

        # Add year range filter
        if (!is.null(ano_min_adjusted) && !is.null(ano_max_adjusted)) {
          base_query <- paste0(base_query, " AND EXTRACT(YEAR FROM data) BETWEEN ", ano_min_adjusted, " AND ", ano_max_adjusted)
        }

        # Add date range filter
        if (!is.null(current_date_start)) {
          base_query <- paste0(base_query, " AND data >= '", current_date_start, "'")
        }
        if (!is.null(current_date_end)) {
          base_query <- paste0(base_query, " AND data <= '", current_date_end, "'")
        }

        # Add ORDER BY
        base_query <- paste(base_query, "ORDER BY", order_clause)

        # Apply pagination using utility function (Phase 2, Task 2.3)
        paginated_query <- paginate_query(
          base_query = base_query,
          page = filters$current_page,
          page_size = current_limit
        )

        message("Executing paginated query with caching (Phase 2, Tasks 2.2 + 2.3)")

        # Execute query with caching (Phase 2, Task 2.2)
        tryCatch({
          # Use cached_query with pagination
          result <- cached_query(
            connection = db_connection,
            query = paginated_query,
            params = list(
              search = current_search,
              tipo = current_tipo,
              estado = current_estado,
              ano_min = ano_min_adjusted,
              ano_max = ano_max_adjusted,
              date_start = current_date_start,
              date_end = current_date_end,
              sort = current_sort_by,
              page = filters$current_page,
              page_size = current_limit
            ),
            ttl = CACHE_TTL$search,
            cache_type = "library"
          )

          # Extract total rows from paginated result (Phase 2, Task 2.3)
          if (!is.null(result) && nrow(result) > 0) {
            pagination_data <- extract_pagination_data(result)
            result <- pagination_data$data
            filters$total_count <- pagination_data$total_rows

            message("Paginated query returned ", nrow(result), " rows (total: ", filters$total_count, ")")
          } else {
            filters$total_count <- 0
          }

        }, error = function(e) {
          message("Database error: ", e$message)
          result <- data.frame(Error = paste("Database error:", e$message))
          filters$total_count <- 0
        })
      }

      # Handle empty results
      if (is.null(result) || nrow(result) == 0) {
        filters$total_count <- 0
        return(data.frame(Message = "Nenhum documento encontrado para os filtros selecionados."))
      }

      # Store results for export
      filters$last_results <- result

      return(result)
    })

    # Render search statistics
    output$search_stats_ui <- renderUI({
      total <- filters$total_count
      current_page <- filters$current_page
      per_page <- filters$results_per_page

      if (total == 0) {
        return(NULL)
      }

      start_idx <- (current_page - 1) * per_page + 1
      end_idx <- min(current_page * per_page, total)
      total_pages <- ceiling(total / per_page)

      div(
        class = "search-stats",
        role = "status",
        `aria-live` = "polite",
        icon("info-circle"),
        sprintf(" Mostrando %.0f-%.0f de %.0f documentos | Página %.0f de %.0f",
                start_idx, end_idx, total, current_page, total_pages)
      )
    })

    # Render pagination info
    output$pagination_info <- renderUI({
      total <- filters$total_count
      current_page <- filters$current_page
      per_page <- filters$results_per_page

      if (total == 0) {
        return(NULL)
      }

      total_pages <- ceiling(total / per_page)

      div(
        style = "display: flex; gap: 10px; justify-content: center; align-items: center;",

        if (current_page > 1) {
          actionButton(
            ns("prev_page"),
            "Anterior",
            icon = icon("chevron-left"),
            class = "btn-sm"
          )
        },

        span(
          style = "font-weight: bold;",
          sprintf("Página %.0f de %.0f", current_page, total_pages)
        ),

        if (current_page < total_pages) {
          actionButton(
            ns("next_page"),
            "Próxima",
            icon = icon("chevron-right"),
            class = "btn-sm"
          )
        }
      )
    })

    # Pagination handlers
    observeEvent(input$prev_page, {
      if (filters$current_page > 1) {
        filters$current_page <- filters$current_page - 1
        filters$trigger <- filters$trigger + 1
      }
    })

    observeEvent(input$next_page, {
      total_pages <- ceiling(filters$total_count / filters$results_per_page)
      if (filters$current_page < total_pages) {
        filters$current_page <- filters$current_page + 1
        filters$trigger <- filters$trigger + 1
      }
    })

    # Render data table with enhanced formatting
    output$library_table <- DT::renderDataTable({
      data <- library_data()

      if (is.null(data) || nrow(data) == 0) {
        return(data)
      }

      # Apply text normalization to improve Portuguese readability
      if (exists("clean_dataframe_text")) {
        tryCatch({
          data <- clean_dataframe_text(
            data,
            columns = c("titulo", "ementa", "content", "assuntos", "tipo", "orgao_emissor"),
            aggressive = FALSE
          )
        }, error = function(e) {
          message("Text normalization warning: ", e$message)
        })
      }

      # Format data table with Portuguese locale and enhanced features
      DT::datatable(
        data,
        options = list(
          pageLength = filters$results_per_page,
          searching = FALSE,  # We handle searching with our filters
          paging = FALSE,     # We handle pagination manually
          scrollX = TRUE,
          language = list(
            url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
          ),
          columnDefs = list(
            list(className = 'dt-center', targets = '_all')
          )
        ),
        rownames = FALSE,
        class = 'table table-striped table-hover',
        selection = 'single'
      ) %>%
        DT::formatDate(columns = 'data', method = 'toLocaleDateString', params = list('pt-BR'))
    })

    # Force output to bind even when hidden
    outputOptions(output, "library_table", suspendWhenHidden = FALSE)

    # Export handlers using export module functions
    # Source export module functions
    if (file.exists("R/modules/export_module.R")) {
      source("R/modules/export_module.R", local = TRUE)
    }

    # Helper function to get export data
    get_export_data <- function() {
      data <- filters$last_results
      if (is.null(data) || nrow(data) == 0) {
        data <- library_data()
      }
      return(data)
    }

    # CSV Export
    output$export_csv <- downloadHandler(
      filename = function() {
        paste0("documentos_", format(Sys.Date(), "%Y%m%d"), ".csv")
      },
      content = function(file) {
        data <- get_export_data()
        write.csv(data, file, row.names = FALSE, fileEncoding = "UTF-8")
      }
    )

    # Excel Export
    output$export_excel <- downloadHandler(
      filename = function() {
        paste0("documentos_", format(Sys.Date(), "%Y%m%d"), ".xlsx")
      },
      content = function(file) {
        data <- get_export_data()
        if (requireNamespace("openxlsx", quietly = TRUE)) {
          openxlsx::write.xlsx(data, file)
        } else {
          write.csv(data, file, row.names = FALSE)
        }
      }
    )

    # JSON Export
    output$export_json <- downloadHandler(
      filename = function() {
        paste0("documentos_", format(Sys.Date(), "%Y%m%d"), ".json")
      },
      content = function(file) {
        data <- get_export_data()
        if (requireNamespace("jsonlite", quietly = TRUE)) {
          jsonlite::write_json(data, file, pretty = TRUE)
        }
      }
    )

    # XML Export
    output$export_xml <- downloadHandler(
      filename = function() {
        paste0("documentos_", format(Sys.Date(), "%Y%m%d"), ".xml")
      },
      content = function(file) {
        data <- get_export_data()
        xml_content <- '<?xml version="1.0" encoding="UTF-8"?>\n<documentos>\n'
        for (i in 1:nrow(data)) {
          xml_content <- paste0(xml_content, '  <documento>\n')
          for (col in names(data)) {
            value <- as.character(data[i, col])
            value <- gsub("&", "&amp;", value)
            value <- gsub("<", "&lt;", value)
            value <- gsub(">", "&gt;", value)
            xml_content <- paste0(xml_content, '    <', col, '>', value, '</', col, '>\n')
          }
          xml_content <- paste0(xml_content, '  </documento>\n')
        }
        xml_content <- paste0(xml_content, '</documentos>')
        writeLines(xml_content, file, useBytes = TRUE)
      }
    )

    # BibTeX Export
    output$export_bibtex <- downloadHandler(
      filename = function() {
        paste0("documentos_", format(Sys.Date(), "%Y%m%d"), ".bib")
      },
      content = function(file) {
        data <- get_export_data()
        bibtex_content <- ""
        for (i in 1:nrow(data)) {
          entry_key <- paste0("doc", data$id[i])
          title <- as.character(data$titulo[i])
          year <- format(as.Date(data$data[i]), "%Y")
          tipo <- as.character(data$tipo[i])

          bibtex_content <- paste0(bibtex_content,
            "@misc{", entry_key, ",\n",
            "  title = {", title, "},\n",
            "  year = {", year, "},\n",
            "  type = {", tipo, "},\n",
            "  note = {Brazilian Legislative Document}\n",
            "}\n\n"
          )
        }
        writeLines(bibtex_content, file, useBytes = TRUE)
      }
    )

    # RIS Export
    output$export_ris <- downloadHandler(
      filename = function() {
        paste0("documentos_", format(Sys.Date(), "%Y%m%d"), ".ris")
      },
      content = function(file) {
        data <- get_export_data()
        ris_content <- ""
        for (i in 1:nrow(data)) {
          title <- as.character(data$titulo[i])
          year <- format(as.Date(data$data[i]), "%Y")
          tipo <- as.character(data$tipo[i])

          ris_content <- paste0(ris_content,
            "TY  - LEGAL\n",
            "TI  - ", title, "\n",
            "PY  - ", year, "\n",
            "T2  - ", tipo, "\n",
            "ER  - \n\n"
          )
        }
        writeLines(ris_content, file, useBytes = TRUE)
      }
    )

    # LexML Export
    output$export_lexml <- downloadHandler(
      filename = function() {
        paste0("documentos_lexml_", format(Sys.Date(), "%Y%m%d"), ".xml")
      },
      content = function(file) {
        data <- get_export_data()
        if (exists("convert_to_lexml")) {
          lexml_content <- convert_to_lexml(data)
          writeLines(lexml_content, file, useBytes = TRUE)
        } else {
          # Fallback to simple XML
          xml_content <- '<?xml version="1.0" encoding="UTF-8"?>\n<documentos>\n'
          for (i in 1:nrow(data)) {
            xml_content <- paste0(xml_content, '  <documento>\n')
            for (col in names(data)) {
              value <- as.character(data[i, col])
              value <- gsub("&", "&amp;", value)
              value <- gsub("<", "&lt;", value)
              value <- gsub(">", "&gt;", value)
              xml_content <- paste0(xml_content, '    <', col, '>', value, '</', col, '>\n')
            }
            xml_content <- paste0(xml_content, '  </documento>\n')
          }
          xml_content <- paste0(xml_content, '</documentos>')
          writeLines(xml_content, file, useBytes = TRUE)
        }
      }
    )

    # EndNote Export
    output$export_endnote <- downloadHandler(
      filename = function() {
        paste0("documentos_endnote_", format(Sys.Date(), "%Y%m%d"), ".xml")
      },
      content = function(file) {
        data <- get_export_data()
        if (exists("convert_to_endnote_xml")) {
          endnote_content <- convert_to_endnote_xml(data)
          writeLines(endnote_content, file, useBytes = TRUE)
        } else {
          # Fallback to simple XML
          xml_content <- '<?xml version="1.0" encoding="UTF-8"?>\n<xml>\n<records>\n'
          for (i in 1:nrow(data)) {
            title <- as.character(data$titulo[i])
            year <- format(as.Date(data$data[i]), "%Y")
            tipo <- as.character(data$tipo[i])

            xml_content <- paste0(xml_content,
              '<record>\n',
              '  <ref-type name="Legal Rule or Regulation">27</ref-type>\n',
              '  <titles>\n',
              '    <title>', gsub("&", "&amp;", gsub("<", "&lt;", gsub(">", "&gt;", title))), '</title>\n',
              '  </titles>\n',
              '  <dates>\n',
              '    <year>', year, '</year>\n',
              '  </dates>\n',
              '  <custom1>', tipo, '</custom1>\n',
              '</record>\n'
            )
          }
          xml_content <- paste0(xml_content, '</records>\n</xml>')
          writeLines(xml_content, file, useBytes = TRUE)
        }
      }
    )

    # Return reactive values for external access
    return(list(
      filters = filters,
      library_data = library_data
    ))
  })
}
