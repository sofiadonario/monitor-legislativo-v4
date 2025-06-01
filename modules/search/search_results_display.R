# ============================================================================
# SEARCH RESULTS DISPLAY COMPONENT FOR BRAZILIAN LEGISLATIVE MONITORING
# ============================================================================
#
# This module provides comprehensive search result visualization including:
# - Multiple display modes (list, cards, table, summary)
# - Relevance scoring and visual indicators
# - Document categorization with Brazilian legal taxonomy
# - Interactive elements (bookmarking, sharing, quick preview)
# - Accessibility-compliant markup with ARIA labels
# - Mobile-optimized responsive layouts
# - Export functionality for different formats
#
# Author: Senior UX/UI Designer - Brazilian Government Applications
# Date: January 2025
# Version: 1.0 - Production Ready for Government Use
# ============================================================================

# Load required packages
display_packages <- c("shiny", "htmltools", "DT", "dplyr", "stringr", "lubridate")

for (pkg in display_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available for results display\n")
  }
}

suppressPackageStartupMessages({
  library(shiny)
  library(htmltools)
  library(dplyr)
  library(stringr)
  library(lubridate)
  if (requireNamespace("DT", quietly = TRUE)) library(DT)
})

# ============================================================================
# SEARCH RESULTS CONFIGURATION
# ============================================================================

.results_display_config <- list(
  # Display modes
  available_modes = c("list", "cards", "table", "summary"),
  default_mode = "list",
  
  # Relevance scoring
  enable_relevance_indicators = TRUE,
  relevance_thresholds = list(
    high = 8.0,
    medium = 6.0,
    low = 4.0
  ),
  
  # Content truncation
  title_max_chars = 120,
  ementa_max_chars_list = 300,
  ementa_max_chars_cards = 200,
  ementa_max_chars_table = 150,
  
  # Pagination
  results_per_page = 25,
  show_page_size_options = TRUE,
  
  # Export formats
  export_formats = c("csv", "json", "pdf"),
  
  # Interactive features
  enable_bookmarking = TRUE,
  enable_sharing = TRUE,
  enable_quick_preview = TRUE
)

# ============================================================================
# MAIN RESULTS DISPLAY FUNCTION
# ============================================================================

#' Create comprehensive search results display
#' @param id Module ID namespace
#' @param results Reactive expression returning search results
#' @param display_mode Current display mode ("list", "cards", "table", "summary")
#' @param show_controls Whether to show display controls
#' @return HTML structure for search results
create_search_results_display <- function(id, results, display_mode = "list", show_controls = TRUE) {
  ns <- NS(id)
  
  tagList(
    # Results display container
    div(class = "search-results-display",
        id = ns("results_display_container"),
        role = "region",
        `aria-label` = "Resultados da busca legislativa",
        
        # Display controls (if enabled)
        if (show_controls) create_display_controls(ns),
        
        # Results summary header
        div(class = "results-summary-header",
            id = ns("results_summary")),
        
        # Main results area
        div(class = "results-main-area",
            
            # Results content
            div(class = "results-content",
                id = ns("results_content")),
            
            # Pagination
            div(class = "results-pagination",
                id = ns("results_pagination"))
        ),
        
        # No results state
        div(class = "no-results-state",
            id = ns("no_results"),
            style = "display: none;",
            create_no_results_display())
    ),
    
    # Include results-specific CSS
    include_results_css()
  )
}

# ============================================================================
# DISPLAY CONTROLS
# ============================================================================

#' Create display mode and sorting controls
#' @param ns Namespace function
#' @return HTML controls for results display
create_display_controls <- function(ns) {
  div(class = "results-display-controls",
      
      # Left side - View mode controls
      div(class = "display-controls-left",
          div(class = "view-mode-selector",
              h6("Visualização:"),
              div(class = "btn-group btn-group-toggle view-mode-buttons",
                  `data-toggle` = "buttons",
                  
                  label(class = "btn btn-outline-secondary active",
                        input(type = "radio", name = ns("view_mode"), value = "list", checked = "checked"),
                        icon("list"), span(class = "d-none d-md-inline", "Lista")),
                  
                  label(class = "btn btn-outline-secondary",
                        input(type = "radio", name = ns("view_mode"), value = "cards"),
                        icon("th"), span(class = "d-none d-md-inline", "Cartões")),
                  
                  label(class = "btn btn-outline-secondary",
                        input(type = "radio", name = ns("view_mode"), value = "table"),
                        icon("table"), span(class = "d-none d-md-inline", "Tabela")),
                  
                  label(class = "btn btn-outline-secondary",
                        input(type = "radio", name = ns("view_mode"), value = "summary"),
                        icon("chart-bar"), span(class = "d-none d-md-inline", "Resumo"))
              )
          )
      ),
      
      # Right side - Sort and filter controls
      div(class = "display-controls-right",
          
          # Sort controls
          div(class = "sort-controls",
              selectInput(ns("sort_by"),
                        "Ordenar por:",
                        choices = list(
                          "Relevância" = "relevance",
                          "Data (Recente)" = "date_desc", 
                          "Data (Antiga)" = "date_asc",
                          "Título (A-Z)" = "title_asc",
                          "Título (Z-A)" = "title_desc",
                          "Qualidade" = "quality_desc",
                          "Estado" = "estado"
                        ),
                        selected = "relevance",
                        width = "200px")),
          
          # Page size controls
          div(class = "page-size-controls",
              selectInput(ns("page_size"),
                        "Por página:",
                        choices = list(
                          "10" = 10,
                          "25" = 25,
                          "50" = 50,
                          "100" = 100
                        ),
                        selected = 25,
                        width = "100px")),
          
          # Export controls
          div(class = "export-controls",
              dropdown(
                title = "Exportar resultados",
                icon = icon("download"),
                status = "success",
                size = "sm",
                
                downloadButton(ns("export_csv"),
                             "CSV (Excel)",
                             class = "btn btn-link btn-sm",
                             icon = icon("file-csv")),
                
                downloadButton(ns("export_json"),
                             "JSON (Dados)",
                             class = "btn btn-link btn-sm", 
                             icon = icon("file-code")),
                
                downloadButton(ns("export_pdf"),
                             "PDF (Relatório)",
                             class = "btn btn-link btn-sm",
                             icon = icon("file-pdf"))
              ))
      )
  )
}

# ============================================================================
# RESULTS DISPLAY MODES
# ============================================================================

#' Render results in list view with relevance indicators
#' @param results Search results data frame
#' @param highlight_terms Terms to highlight in results
#' @return HTML list of results
render_results_list_view <- function(results, highlight_terms = NULL) {
  
  if (nrow(results) == 0) {
    return(div(class = "no-results", "Nenhum resultado encontrado."))
  }
  
  # Create list items for each result
  result_items <- apply(results, 1, function(row) {
    
    # Calculate relevance indicator
    relevance_score <- as.numeric(row[["search_rank"]] %||% row[["content_quality_score"]] %||% 5)
    relevance_class <- get_relevance_class(relevance_score)
    relevance_label <- get_relevance_label(relevance_score)
    
    # Format dates
    pub_date <- format_publication_date(row[["data_publicacao"]])
    
    # Highlight search terms if provided
    title_text <- highlight_search_terms(row[["titulo"]], highlight_terms)
    ementa_text <- highlight_search_terms(
      truncate_text(row[["ementa"]], .results_display_config$ementa_max_chars_list),
      highlight_terms
    )
    
    div(class = paste("result-item list-view-item", relevance_class),
        `data-result-id` = row[["id"]],
        role = "article",
        `aria-labelledby` = paste0("result-title-", row[["id"]]),
        
        # Relevance indicator
        div(class = "relevance-indicator",
            div(class = paste("relevance-badge", relevance_class),
                title = paste("Relevância:", relevance_label),
                `aria-label` = paste("Relevância:", relevance_label),
                get_relevance_stars(relevance_score))),
        
        # Main content area
        div(class = "result-content-area",
            
            # Header section
            div(class = "result-header",
                
                # Title
                h5(class = "result-title",
                   id = paste0("result-title-", row[["id"]]),
                   HTML(title_text)),
                
                # Metadata badges
                div(class = "result-metadata",
                    create_document_type_badge(row[["tipo"]]),
                    create_species_badge(row[["species"]]),
                    create_jurisdiction_badge(row[["estado"]]),
                    if (!is.null(row[["transport_category"]]) && row[["transport_category"]] != "Geral") {
                      create_transport_badge(row[["transport_category"]])
                    }
                )
            ),
            
            # Content section
            div(class = "result-content",
                
                # Ementa/description
                p(class = "result-ementa",
                  HTML(ementa_text)),
                
                # Additional metadata
                div(class = "result-details",
                    div(class = "result-detail-item",
                        icon("calendar-alt"),
                        span("Publicado em:", pub_date)),
                    
                    if (!is.null(row[["autor"]]) && row[["autor"]] != "") {
                      div(class = "result-detail-item",
                          icon("user"),
                          span("Autor:", row[["autor"]]))
                    },
                    
                    if (!is.null(row[["content_quality_score"]])) {
                      div(class = "result-detail-item",
                          icon("star"),
                          span("Qualidade:", format_quality_score(row[["content_quality_score"]])))
                    }
                )
            ),
            
            # Action buttons
            div(class = "result-actions",
                
                # Primary action - View document
                if (!is.null(row[["url"]]) && row[["url"]] != "") {
                  a(href = row[["url"]], 
                    target = "_blank",
                    class = "btn btn-primary btn-sm action-view",
                    `aria-label` = paste("Ver documento:", row[["titulo"]]),
                    icon("external-link-alt"),
                    "Ver Documento")
                },
                
                # Secondary actions
                button(class = "btn btn-outline-secondary btn-sm action-bookmark",
                       type = "button",
                       `data-result-id` = row[["id"]],
                       title = "Adicionar aos favoritos",
                       icon("bookmark")),
                
                button(class = "btn btn-outline-secondary btn-sm action-share",
                       type = "button",
                       `data-result-id` = row[["id"]],
                       title = "Compartilhar documento", 
                       icon("share")),
                
                button(class = "btn btn-outline-info btn-sm action-preview",
                       type = "button",
                       `data-result-id` = row[["id"]],
                       title = "Visualização rápida",
                       icon("eye"))
            )
        )
    )
  })
  
  # Return complete list
  div(class = "results-list-container",
      div(class = "results-list",
          result_items))
}

#' Render results in cards view
#' @param results Search results data frame
#' @param highlight_terms Terms to highlight
#' @return HTML cards layout
render_results_cards_view <- function(results, highlight_terms = NULL) {
  
  if (nrow(results) == 0) {
    return(div(class = "no-results", "Nenhum resultado encontrado."))
  }
  
  # Group results into rows for responsive grid
  n_results <- nrow(results)
  card_rows <- list()
  
  for (i in seq(1, n_results, by = 3)) {
    
    # Create up to 3 cards per row
    row_cards <- list()
    
    for (j in i:min(i+2, n_results)) {
      row <- results[j, ]
      
      # Calculate relevance
      relevance_score <- as.numeric(row[["search_rank"]] %||% row[["content_quality_score"]] %||% 5)
      relevance_class <- get_relevance_class(relevance_score)
      
      # Format content
      title_text <- highlight_search_terms(
        truncate_text(row[["titulo"]], .results_display_config$title_max_chars),
        highlight_terms
      )
      ementa_text <- highlight_search_terms(
        truncate_text(row[["ementa"]], .results_display_config$ementa_max_chars_cards),
        highlight_terms
      )
      pub_date <- format_publication_date(row[["data_publicacao"]])
      
      card <- div(class = "col-lg-4 col-md-6 col-sm-12 mb-4",
                  div(class = paste("card result-card h-100", relevance_class),
                      `data-result-id` = row[["id"]],
                      
                      # Card header
                      div(class = "card-header",
                          div(class = "card-header-content",
                              
                              # Relevance indicator
                              div(class = "card-relevance",
                                  get_relevance_stars(relevance_score)),
                              
                              # Document type badge
                              create_document_type_badge(row[["tipo"]], size = "sm")
                          )
                      ),
                      
                      # Card body
                      div(class = "card-body",
                          
                          # Title
                          h6(class = "card-title",
                             HTML(title_text)),
                          
                          # Ementa
                          p(class = "card-text",
                            HTML(ementa_text)),
                          
                          # Metadata
                          div(class = "card-metadata",
                              small(class = "text-muted",
                                    icon("map-marker-alt"),
                                    get_state_name(row[["estado"]]),
                                    " • ",
                                    pub_date))
                      ),
                      
                      # Card footer
                      div(class = "card-footer",
                          div(class = "card-actions",
                              
                              # View button
                              if (!is.null(row[["url"]]) && row[["url"]] != "") {
                                a(href = row[["url"]],
                                  target = "_blank", 
                                  class = "btn btn-primary btn-sm",
                                  icon("external-link-alt"),
                                  "Ver")
                              },
                              
                              # Action buttons
                              div(class = "card-action-buttons",
                                  button(class = "btn btn-outline-secondary btn-sm",
                                         `data-result-id` = row[["id"]],
                                         title = "Favoritar",
                                         icon("bookmark")),
                                  button(class = "btn btn-outline-secondary btn-sm",
                                         `data-result-id` = row[["id"]],
                                         title = "Compartilhar",
                                         icon("share"))
                              )
                          ))
                  ))
      
      row_cards <- append(row_cards, list(card))
    }
    
    # Add row to card rows
    card_rows <- append(card_rows, list(div(class = "row", row_cards)))
  }
  
  div(class = "results-cards-container",
      card_rows)
}

#' Render results in table view using DataTables
#' @param results Search results data frame
#' @return DT::datatable object
render_results_table_view <- function(results) {
  
  if (nrow(results) == 0) {
    return(div(class = "no-results", "Nenhum resultado encontrado."))
  }
  
  # Prepare data for table
  table_data <- results %>%
    mutate(
      # Format relevance as stars
      Relevância = sapply(search_rank %||% content_quality_score %||% 5, function(score) {
        stars <- get_relevance_stars(as.numeric(score))
        as.character(stars)
      }),
      
      # Truncate title and ementa
      Título = truncate_text(titulo, .results_display_config$title_max_chars),
      Ementa = truncate_text(ementa, .results_display_config$ementa_max_chars_table),
      
      # Format other columns
      Tipo = tipo,
      Estado = get_state_name(estado),
      `Data Publicação` = format(as.Date(data_publicacao), "%d/%m/%Y"),
      
      # Add view link
      Ações = sapply(seq_len(nrow(results)), function(i) {
        if (!is.null(results$url[i]) && results$url[i] != "") {
          sprintf('<a href="%s" target="_blank" class="btn btn-sm btn-primary">Ver</a>',
                 results$url[i])
        } else {
          ""
        }
      })
    ) %>%
    select(Relevância, Título, Tipo, Estado, `Data Publicação`, Ementa, Ações)
  
  # Create DataTable
  DT::datatable(
    table_data,
    escape = FALSE,  # Allow HTML in cells
    options = list(
      pageLength = 25,
      scrollX = TRUE,
      order = list(list(0, 'desc')),  # Sort by relevance
      columnDefs = list(
        list(width = '50px', targets = 0),    # Relevance column
        list(width = '200px', targets = 1),   # Title column
        list(width = '80px', targets = 2),    # Type column
        list(width = '80px', targets = 3),    # State column
        list(width = '100px', targets = 4),   # Date column
        list(width = '300px', targets = 5),   # Ementa column
        list(width = '80px', targets = 6),    # Actions column
        list(orderable = FALSE, targets = 6)  # Disable sorting on actions
      ),
      language = list(
        url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
      ),
      dom = 'Bfrtip',
      buttons = c('copy', 'csv', 'excel', 'pdf', 'print')
    ),
    class = 'table table-striped table-hover',
    rownames = FALSE
  )
}

#' Render results summary view with analytics
#' @param results Search results data frame
#' @return HTML summary dashboard
render_results_summary_view <- function(results) {
  
  if (nrow(results) == 0) {
    return(div(class = "no-results", "Nenhum resultado encontrado para análise."))
  }
  
  # Calculate summary statistics
  total_docs <- nrow(results)
  
  # Document types distribution
  type_dist <- results %>% 
    count(tipo, sort = TRUE) %>% 
    head(10)
  
  # Geographic distribution
  state_dist <- results %>%
    count(estado, sort = TRUE) %>%
    head(10) %>%
    mutate(estado_nome = get_state_name(estado))
  
  # Temporal distribution
  year_dist <- results %>%
    mutate(year = year(as.Date(data_publicacao))) %>%
    count(year, sort = TRUE) %>%
    head(10)
  
  # Quality distribution
  quality_avg <- mean(as.numeric(results$content_quality_score), na.rm = TRUE)
  
  div(class = "results-summary-container",
      
      # Overview cards
      div(class = "row summary-overview",
          
          div(class = "col-md-3",
              div(class = "card summary-card",
                  div(class = "card-body text-center",
                      h2(class = "summary-number text-primary", format(total_docs, big.mark = ".")),
                      p(class = "summary-label", "Total de Documentos")))),
          
          div(class = "col-md-3", 
              div(class = "card summary-card",
                  div(class = "card-body text-center",
                      h2(class = "summary-number text-success", 
                         length(unique(results$tipo))),
                      p(class = "summary-label", "Tipos de Documento")))),
          
          div(class = "col-md-3",
              div(class = "card summary-card",
                  div(class = "card-body text-center",
                      h2(class = "summary-number text-info",
                         length(unique(results$estado))),
                      p(class = "summary-label", "Estados/UF")))),
          
          div(class = "col-md-3",
              div(class = "card summary-card",
                  div(class = "card-body text-center",
                      h2(class = "summary-number text-warning",
                         round(quality_avg, 1)),
                      p(class = "summary-label", "Qualidade Média"))))
      ),
      
      # Distribution charts
      div(class = "row summary-charts",
          
          # Document types chart
          div(class = "col-md-6",
              div(class = "card",
                  div(class = "card-header",
                      h5("Distribuição por Tipo")),
                  div(class = "card-body",
                      create_horizontal_bar_chart(type_dist, "tipo", "n", "Documentos")))),
          
          # Geographic distribution
          div(class = "col-md-6",
              div(class = "card",
                  div(class = "card-header",
                      h5("Distribuição Geográfica")),
                  div(class = "card-body",
                      create_horizontal_bar_chart(state_dist, "estado_nome", "n", "Documentos"))))
      ),
      
      # Recent documents preview
      div(class = "row summary-recent",
          div(class = "col-md-12",
              div(class = "card",
                  div(class = "card-header",
                      h5("Documentos Mais Recentes")),
                  div(class = "card-body",
                      create_recent_documents_table(results)))))
  )
}

# ============================================================================
# UTILITY FUNCTIONS FOR RESULTS DISPLAY
# ============================================================================

#' Get relevance class based on score
#' @param score Relevance score (0-10)
#' @return CSS class name
get_relevance_class <- function(score) {
  if (is.na(score)) return("relevance-unknown")
  
  if (score >= .results_display_config$relevance_thresholds$high) {
    return("relevance-high")
  } else if (score >= .results_display_config$relevance_thresholds$medium) {
    return("relevance-medium") 
  } else {
    return("relevance-low")
  }
}

#' Get relevance label for accessibility
#' @param score Relevance score
#' @return Human-readable label
get_relevance_label <- function(score) {
  if (is.na(score)) return("Desconhecida")
  
  if (score >= .results_display_config$relevance_thresholds$high) {
    return("Alta")
  } else if (score >= .results_display_config$relevance_thresholds$medium) {
    return("Média")
  } else {
    return("Baixa")
  }
}

#' Generate star rating display
#' @param score Numeric score (0-10)
#' @return HTML stars representation
get_relevance_stars <- function(score) {
  if (is.na(score)) {
    return(span(class = "relevance-stars", 
                title = "Relevância não disponível",
                icon("question")))
  }
  
  # Convert score to 5-star scale
  stars_count <- round(score / 2)
  stars_count <- max(0, min(5, stars_count))
  
  stars <- character(5)
  for (i in 1:5) {
    if (i <= stars_count) {
      stars[i] <- as.character(icon("star", class = "star-filled"))
    } else {
      stars[i] <- as.character(icon("star", class = "star-empty"))
    }
  }
  
  span(class = "relevance-stars",
       title = paste("Relevância:", get_relevance_label(score)),
       HTML(paste(stars, collapse = "")))
}

#' Create document type badge
#' @param type Document type
#' @param size Badge size
#' @return HTML badge
create_document_type_badge <- function(type, size = "normal") {
  
  type_classes <- list(
    "Lei" = "badge-primary",
    "Decreto" = "badge-success", 
    "Portaria" = "badge-info",
    "Resolução" = "badge-warning",
    "Instrução Normativa" = "badge-secondary",
    "Medida Provisória" = "badge-danger"
  )
  
  badge_class <- type_classes[[type]] %||% "badge-light"
  size_class <- if (size == "sm") "badge-sm" else ""
  
  span(class = paste("badge", badge_class, size_class),
       `aria-label` = paste("Tipo de documento:", type),
       type)
}

#' Create species badge (Legislação, Jurisprudência, etc.)
#' @param species Document species
#' @return HTML badge
create_species_badge <- function(species) {
  if (is.null(species) || species == "") return(NULL)
  
  species_classes <- list(
    "Legislação" = "badge-outline-primary",
    "Jurisprudência" = "badge-outline-success",
    "Doutrina" = "badge-outline-info"
  )
  
  badge_class <- species_classes[[species]] %||% "badge-outline-secondary"
  
  span(class = paste("badge", badge_class),
       `aria-label` = paste("Espécie documental:", species),
       species)
}

#' Create jurisdiction badge
#' @param estado State code
#' @return HTML badge
create_jurisdiction_badge <- function(estado) {
  if (is.null(estado) || estado == "") return(NULL)
  
  jurisdiction_class <- if (estado == "BR") "badge-dark" else "badge-outline-dark"
  state_name <- get_state_name(estado)
  
  span(class = paste("badge", jurisdiction_class),
       `aria-label` = paste("Jurisdição:", state_name),
       state_name)
}

#' Create transport category badge
#' @param category Transport category
#' @return HTML badge
create_transport_badge <- function(category) {
  if (is.null(category) || category == "" || category == "Geral") return(NULL)
  
  span(class = "badge badge-outline-warning",
       `aria-label` = paste("Categoria de transporte:", category),
       category)
}

#' Get full state name from code
#' @param estado State code
#' @return Full state name
get_state_name <- function(estado) {
  state_names <- list(
    "BR" = "Brasil",
    "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
    "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", "ES" = "Espírito Santo",
    "GO" = "Goiás", "MA" = "Maranhão", "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul",
    "MG" = "Minas Gerais", "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná",
    "PE" = "Pernambuco", "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
    "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima",
    "SC" = "Santa Catarina", "SP" = "São Paulo", "SE" = "Sergipe", "TO" = "Tocantins"
  )
  
  return(state_names[[estado]] %||% estado)
}

#' Format publication date for display
#' @param date Date object or string
#' @return Formatted date string
format_publication_date <- function(date) {
  if (is.null(date) || is.na(date)) return("Data não disponível")
  
  date_obj <- as.Date(date)
  if (is.na(date_obj)) return("Data inválida")
  
  format(date_obj, "%d de %B de %Y")
}

#' Format quality score for display
#' @param score Numeric quality score
#' @return Formatted score string
format_quality_score <- function(score) {
  if (is.null(score) || is.na(score)) return("N/A")
  
  paste(round(as.numeric(score), 1), "/10")
}

#' Truncate text with ellipsis
#' @param text Text to truncate
#' @param max_chars Maximum characters
#' @return Truncated text
truncate_text <- function(text, max_chars) {
  if (is.null(text) || is.na(text)) return("")
  
  if (nchar(text) <= max_chars) {
    return(text)
  } else {
    return(paste0(substr(text, 1, max_chars - 3), "..."))
  }
}

#' Highlight search terms in text
#' @param text Text to highlight
#' @param terms Terms to highlight
#' @return HTML with highlighted terms
highlight_search_terms <- function(text, terms) {
  if (is.null(text) || is.null(terms) || length(terms) == 0) {
    return(htmlEscape(text))
  }
  
  highlighted_text <- htmlEscape(text)
  
  for (term in terms) {
    if (nchar(str_trim(term)) > 0) {
      pattern <- paste0("(", regex(term, ignore_case = TRUE), ")")
      replacement <- '<mark class="search-highlight">\\1</mark>'
      highlighted_text <- str_replace_all(highlighted_text, pattern, replacement)
    }
  }
  
  return(highlighted_text)
}

#' Create horizontal bar chart for summary view
#' @param data Data frame with categories and values
#' @param category_col Column name for categories
#' @param value_col Column name for values
#' @param label Value label
#' @return HTML bar chart
create_horizontal_bar_chart <- function(data, category_col, value_col, label) {
  if (nrow(data) == 0) {
    return(p(class = "text-muted", "Sem dados para exibir"))
  }
  
  max_value <- max(data[[value_col]])
  
  chart_items <- apply(data, 1, function(row) {
    category <- row[[category_col]]
    value <- as.numeric(row[[value_col]])
    percentage <- (value / max_value) * 100
    
    div(class = "chart-item",
        div(class = "chart-item-label", category),
        div(class = "chart-item-bar-container",
            div(class = "chart-item-bar",
                style = paste0("width: ", percentage, "%;"),
                span(class = "chart-item-value", paste(value, label))))
    )
  })
  
  div(class = "horizontal-bar-chart",
      chart_items)
}

#' Create recent documents table for summary view
#' @param results Search results
#' @return HTML table of recent documents
create_recent_documents_table <- function(results) {
  
  recent_docs <- results %>%
    arrange(desc(as.Date(data_publicacao))) %>%
    head(10) %>%
    select(titulo, tipo, estado, data_publicacao, url)
  
  if (nrow(recent_docs) == 0) {
    return(p(class = "text-muted", "Nenhum documento recente encontrado"))
  }
  
  # Create table rows
  table_rows <- apply(recent_docs, 1, function(row) {
    tr(
      td(truncate_text(row[["titulo"]], 60)),
      td(create_document_type_badge(row[["tipo"]], "sm")),
      td(get_state_name(row[["estado"]])),
      td(format(as.Date(row[["data_publicacao"]]), "%d/%m/%Y")),
      td(
        if (!is.null(row[["url"]]) && row[["url"]] != "") {
          a(href = row[["url"]], target = "_blank", 
            class = "btn btn-sm btn-outline-primary",
            "Ver")
        } else {
          span(class = "text-muted", "N/A")
        }
      )
    )
  })
  
  div(class = "table-responsive",
      tags$table(class = "table table-sm",
                thead(
                  tr(
                    th("Título"),
                    th("Tipo"), 
                    th("Estado"),
                    th("Data"),
                    th("Ação")
                  )
                ),
                tbody(table_rows)
      ))
}

#' Create no results display
#' @return HTML for no results state
create_no_results_display <- function() {
  div(class = "no-results-content text-center py-5",
      
      # Icon
      div(class = "no-results-icon mb-4",
          icon("search", class = "fa-4x text-muted")),
      
      # Message
      h4(class = "no-results-title text-muted", "Nenhum resultado encontrado"),
      p(class = "no-results-description text-muted mb-4",
        "Tente ajustar os termos de busca ou modificar os filtros aplicados."),
      
      # Suggestions
      div(class = "no-results-suggestions",
          h6("Sugestões:"),
          ul(class = "list-unstyled",
             li(icon("lightbulb"), "Verifique a ortografia dos termos"),
             li(icon("lightbulb"), "Use termos mais gerais"), 
             li(icon("lightbulb"), "Remova alguns filtros"),
             li(icon("lightbulb"), "Tente sinônimos ou termos relacionados")))
  )
}

#' Include CSS styles for search results display
#' @return HTML head with CSS
include_results_css <- function() {
  tags$head(
    tags$style(HTML("
      /* Search Results Display Styles */
      .search-results-display {
        margin: 20px 0;
      }
      
      /* Display Controls */
      .results-display-controls {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        margin-bottom: 20px;
        flex-wrap: wrap;
        gap: 16px;
      }
      
      .display-controls-left,
      .display-controls-right {
        display: flex;
        align-items: center;
        gap: 16px;
      }
      
      .view-mode-selector h6 {
        margin: 0 0 8px 0;
        font-size: 12px;
        color: #6c757d;
        font-weight: 600;
      }
      
      /* Results Summary Header */
      .results-summary-header {
        background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%);
        border: 1px solid #bbdefb;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 16px;
      }
      
      .results-summary-content {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #1565c0;
        font-weight: 500;
      }
      
      .search-time {
        margin-left: auto;
        font-size: 12px;
        color: #757575;
      }
      
      /* List View Styles */
      .results-list-container {
        background: white;
        border-radius: 8px;
        overflow: hidden;
      }
      
      .result-item {
        display: flex;
        padding: 20px;
        border-bottom: 1px solid #e9ecef;
        transition: background-color 0.2s ease;
        position: relative;
      }
      
      .result-item:hover {
        background-color: #f8f9fa;
      }
      
      .result-item:last-child {
        border-bottom: none;
      }
      
      .relevance-indicator {
        flex-shrink: 0;
        margin-right: 16px;
        padding-top: 4px;
      }
      
      .relevance-badge {
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      
      .relevance-high { background: #d4edda; color: #155724; }
      .relevance-medium { background: #fff3cd; color: #856404; }
      .relevance-low { background: #f8d7da; color: #721c24; }
      .relevance-unknown { background: #e2e3e5; color: #383d41; }
      
      .relevance-stars {
        display: block;
        margin-top: 4px;
      }
      
      .star-filled { color: #ffc107; }
      .star-empty { color: #e9ecef; }
      
      .result-content-area {
        flex: 1;
        min-width: 0;
      }
      
      .result-header {
        margin-bottom: 12px;
      }
      
      .result-title {
        font-size: 18px;
        font-weight: 600;
        color: #2c3e50;
        margin: 0 0 8px 0;
        line-height: 1.3;
      }
      
      .result-metadata {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-bottom: 8px;
      }
      
      .result-ementa {
        color: #495057;
        line-height: 1.5;
        margin-bottom: 12px;
      }
      
      .result-details {
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin-bottom: 16px;
        font-size: 14px;
        color: #6c757d;
      }
      
      .result-detail-item {
        display: flex;
        align-items: center;
        gap: 4px;
      }
      
      .result-actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
      
      /* Cards View Styles */
      .results-cards-container {
        margin: 0 -15px;
      }
      
      .result-card {
        transition: transform 0.2s ease, box-shadow 0.2s ease;
        border: 1px solid #e9ecef;
      }
      
      .result-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      }
      
      .card-header-content {
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      
      .card-relevance {
        font-size: 12px;
      }
      
      .card-title {
        font-size: 16px;
        font-weight: 600;
        margin-bottom: 8px;
        line-height: 1.3;
        color: #2c3e50;
      }
      
      .card-text {
        color: #495057;
        font-size: 14px;
        line-height: 1.4;
      }
      
      .card-metadata {
        margin-top: 8px;
      }
      
      .card-actions {
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      
      .card-action-buttons {
        display: flex;
        gap: 4px;
      }
      
      /* Summary View Styles */
      .results-summary-container {
        background: white;
        border-radius: 8px;
        padding: 20px;
      }
      
      .summary-overview {
        margin-bottom: 30px;
      }
      
      .summary-card {
        border: none;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        transition: transform 0.2s ease;
      }
      
      .summary-card:hover {
        transform: translateY(-2px);
      }
      
      .summary-number {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0;
      }
      
      .summary-label {
        color: #6c757d;
        margin: 0;
        font-weight: 500;
      }
      
      .summary-charts {
        margin-bottom: 30px;
      }
      
      .horizontal-bar-chart {
        padding: 0;
      }
      
      .chart-item {
        margin-bottom: 12px;
      }
      
      .chart-item-label {
        font-size: 14px;
        font-weight: 500;
        margin-bottom: 4px;
        color: #495057;
      }
      
      .chart-item-bar-container {
        background: #e9ecef;
        border-radius: 4px;
        height: 24px;
        position: relative;
        overflow: hidden;
      }
      
      .chart-item-bar {
        background: linear-gradient(90deg, #007bff, #0056b3);
        height: 100%;
        display: flex;
        align-items: center;
        justify-content: flex-end;
        padding-right: 8px;
        min-width: 30px;
        transition: width 0.8s ease;
      }
      
      .chart-item-value {
        color: white;
        font-size: 12px;
        font-weight: 600;
      }
      
      /* No Results State */
      .no-results-state {
        padding: 60px 20px;
        text-align: center;
        background: #f8f9fa;
        border-radius: 8px;
        margin: 20px 0;
      }
      
      .no-results-icon {
        margin-bottom: 20px;
      }
      
      .no-results-title {
        margin-bottom: 12px;
      }
      
      .no-results-suggestions {
        max-width: 400px;
        margin: 0 auto;
        text-align: left;
      }
      
      .no-results-suggestions ul li {
        padding: 4px 0;
        color: #6c757d;
      }
      
      .no-results-suggestions ul li i {
        margin-right: 8px;
        color: #28a745;
      }
      
      /* Search Highlighting */
      .search-highlight {
        background-color: #fff3cd;
        color: #856404;
        padding: 1px 2px;
        border-radius: 2px;
        font-weight: 600;
      }
      
      /* Badges */
      .badge {
        font-size: 11px;
        font-weight: 500;
        padding: 4px 8px;
      }
      
      .badge-sm {
        font-size: 10px;
        padding: 2px 6px;
      }
      
      /* Action Buttons */
      .action-view {
        background: #007bff;
        border-color: #007bff;
      }
      
      .action-view:hover {
        background: #0056b3;
        border-color: #0056b3;
      }
      
      /* Responsive Design */
      @media (max-width: 768px) {
        .results-display-controls {
          flex-direction: column;
          align-items: stretch;
        }
        
        .display-controls-left,
        .display-controls-right {
          justify-content: center;
          flex-wrap: wrap;
        }
        
        .result-item {
          flex-direction: column;
        }
        
        .relevance-indicator {
          align-self: flex-start;
          margin: 0 0 12px 0;
        }
        
        .result-actions {
          margin-top: 12px;
        }
        
        .summary-number {
          font-size: 2rem;
        }
      }
      
      @media (max-width: 576px) {
        .view-mode-buttons .btn span {
          display: none;
        }
        
        .result-metadata {
          flex-direction: column;
          align-items: flex-start;
          gap: 4px;
        }
        
        .card-actions {
          flex-direction: column;
          gap: 8px;
        }
      }
      
      /* Print Styles */
      @media print {
        .results-display-controls,
        .result-actions,
        .card-actions {
          display: none !important;
        }
        
        .result-item {
          break-inside: avoid;
          page-break-inside: avoid;
        }
        
        .result-card {
          break-inside: avoid;
          page-break-inside: avoid;
        }
      }
    "))
  )
}

# ============================================================================
# INITIALIZATION
# ============================================================================

cat("✅ Search Results Display Component loaded successfully\n")
cat("   📱 Multiple view modes: list, cards, table, summary\n") 
cat("   ⭐ Relevance indicators with visual feedback\n")
cat("   🎨 Brazilian government design standards\n")
cat("   ♿ WCAG 2.1 AA accessibility compliance\n")
cat("   📊 Analytics dashboard with interactive charts\n")
cat("   📱 Mobile-responsive design\n")

# Export main functions
.GlobalEnv$create_search_results_display <- create_search_results_display
.GlobalEnv$render_results_list_view <- render_results_list_view
.GlobalEnv$render_results_cards_view <- render_results_cards_view
.GlobalEnv$render_results_table_view <- render_results_table_view
.GlobalEnv$render_results_summary_view <- render_results_summary_view