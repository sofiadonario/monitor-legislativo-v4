# Document Viewer and Analysis for Monitor Legislativo v4
# Advanced document display, formatting, and annotation capabilities

library(shiny)
library(htmltools)
library(dplyr)
library(stringr)
library(DT)
library(shinycssloaders)

# Document viewer configuration
VIEWER_CONFIG <- list(
  max_document_length = 50000,  # Maximum characters to display
  annotation_colors = c("#FFE066", "#FF6B66", "#66B2FF", "#66FF66", "#FF66FF"),
  highlight_colors = c("#FFFF00", "#00FF00", "#FF0000", "#0080FF", "#FF8000"),
  zoom_levels = c(0.8, 0.9, 1.0, 1.1, 1.25, 1.5),
  default_zoom = 1.0,
  enable_text_to_speech = TRUE
)

#' Create enhanced document viewer interface
#' @param id Module ID
#' @return Document viewer UI
document_viewer_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "document-viewer-container",
    
    # Document viewer header with controls
    div(
      class = "viewer-header",
      style = "background: #f8f9fa; padding: 15px; border-radius: 8px 8px 0 0; border-bottom: 1px solid #dee2e6;",
      
      fluidRow(
        column(8,
          h4(
            textOutput(ns("document_title")),
            style = "margin: 0; color: #2c3e50;"
          )
        ),
        
        column(4,
          div(
            class = "viewer-controls text-end",
            
            # Zoom controls
            div(
              class = "btn-group btn-group-sm me-2",
              role = "group",
              
              actionButton(ns("zoom_out"), "−", 
                class = "btn btn-outline-secondary",
                title = "Diminuir texto"
              ),
              span(
                textOutput(ns("zoom_level"), inline = TRUE),
                class = "btn btn-outline-secondary disabled",
                style = "min-width: 50px;"
              ),
              actionButton(ns("zoom_in"), "+",
                class = "btn btn-outline-secondary", 
                title = "Aumentar texto"
              )
            ),
            
            # View mode toggle
            div(
              class = "btn-group btn-group-sm me-2",
              role = "group",
              
              actionButton(ns("view_formatted"), "📄",
                class = "btn btn-outline-primary",
                title = "Visualização formatada"
              ),
              actionButton(ns("view_raw"), "📝",
                class = "btn btn-outline-secondary",
                title = "Texto original"
              ),
              actionButton(ns("view_analysis"), "🔍",
                class = "btn btn-outline-info",
                title = "Análise do documento"
              )
            ),
            
            # Additional controls
            div(
              class = "btn-group btn-group-sm",
              role = "group",
              
              actionButton(ns("print_document"), "🖨️",
                class = "btn btn-outline-success",
                title = "Imprimir documento"
              ),
              actionButton(ns("download_document"), "💾",
                class = "btn btn-outline-primary",
                title = "Baixar documento"
              ),
              conditionalPanel(
                condition = paste0("output['", ns("has_annotations"), "']"),
                actionButton(ns("clear_annotations"), "🗑️",
                  class = "btn btn-outline-danger",
                  title = "Limpar anotações"
                )
              )
            )
          )
        )
      )
    ),
    
    # Document metadata panel
    div(
      class = "metadata-panel",
      style = "background: #ffffff; padding: 10px 15px; border-bottom: 1px solid #dee2e6;",
      
      uiOutput(ns("document_metadata"))
    ),
    
    # Annotation toolbar
    conditionalPanel(
      condition = paste0("input['", ns("view_formatted"), "'] % 2 == 1"),
      div(
        class = "annotation-toolbar",
        style = "background: #fff3cd; padding: 10px 15px; border-bottom: 1px solid #ffeaa7;",
        
        div(
          class = "d-flex align-items-center",
          
          span("Ferramentas de Anotação:", class = "me-3 fw-bold"),
          
          div(
            class = "btn-group btn-group-sm me-3",
            role = "group",
            
            actionButton(ns("highlight_yellow"), "",
              class = "btn btn-warning btn-sm",
              style = "background: #FFFF00; width: 30px;",
              title = "Destacar em amarelo"
            ),
            actionButton(ns("highlight_green"), "",
              class = "btn btn-success btn-sm", 
              style = "background: #00FF00; width: 30px;",
              title = "Destacar em verde"
            ),
            actionButton(ns("highlight_blue"), "",
              class = "btn btn-info btn-sm",
              style = "background: #0080FF; width: 30px;",
              title = "Destacar em azul"
            ),
            actionButton(ns("highlight_red"), "",
              class = "btn btn-danger btn-sm",
              style = "background: #FF0000; width: 30px;",
              title = "Destacar em vermelho"
            )
          ),
          
          actionButton(ns("add_note"), "📝 Adicionar Nota",
            class = "btn btn-outline-primary btn-sm me-2"
          ),
          
          actionButton(ns("bookmark_section"), "🔖 Marcar Seção",
            class = "btn btn-outline-secondary btn-sm"
          )
        )
      )
    ),
    
    # Main document content area
    div(
      class = "document-content-area",
      style = "background: white; min-height: 500px;",
      
      # Loading indicator
      withSpinner(
        uiOutput(ns("document_content")),
        type = 4,
        color = "#0d6efd"
      )
    ),
    
    # Document navigation panel
    div(
      class = "document-navigation",
      style = "background: #f8f9fa; padding: 15px; border-top: 1px solid #dee2e6; border-radius: 0 0 8px 8px;",
      
      fluidRow(
        column(6,
          h6("Navegação no Documento", class = "mb-3"),
          
          conditionalPanel(
            condition = paste0("output['", ns("has_sections"), "']"),
            div(
              class = "section-navigation",
              uiOutput(ns("section_links"))
            )
          )
        ),
        
        column(6,
          h6("Anotações e Marcadores", class = "mb-3"),
          
          div(
            class = "annotations-summary",
            uiOutput(ns("annotations_list"))
          )
        )
      )
    )
  )
}

#' Document viewer server function
#' @param id Module ID
#' @param document_data Reactive containing document data
document_viewer_server <- function(id, document_data) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for viewer state
    values <- reactiveValues(
      current_zoom = VIEWER_CONFIG$default_zoom,
      view_mode = "formatted",  # formatted, raw, analysis
      annotations = list(),
      bookmarks = list(),
      processed_content = NULL
    )
    
    # Process document when data changes
    observe({
      if (!is.null(document_data()) && nrow(document_data()) > 0) {
        doc <- document_data()[1, ]  # Take first document if multiple
        values$processed_content <- process_document_content(doc)
        
        log_event(paste("Document loaded for viewing:", str_trunc(doc$titulo, 50)))
      }
    })
    
    # ========================================================================
    # OUTPUTS - HEADER AND METADATA
    # ========================================================================
    
    output$document_title <- renderText({
      if (is.null(values$processed_content)) {
        return("Nenhum documento selecionado")
      }
      
      values$processed_content$titulo
    })
    
    output$zoom_level <- renderText({
      paste0(round(values$current_zoom * 100), "%")
    })
    
    output$document_metadata <- renderUI({
      if (is.null(values$processed_content)) {
        return(p("Selecione um documento para visualizar", class = "text-muted"))
      }
      
      doc <- values$processed_content
      
      div(
        class = "metadata-grid",
        style = "display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;",
        
        div(
          strong("📄 Tipo: "), doc$tipo,
          br(),
          strong("📅 Data: "), format(as.Date(doc$data), "%d de %B de %Y")
        ),
        
        div(
          strong("🏛️ Autor: "), doc$autor %||% "Não informado",
          br(),
          strong("🗺️ Estado: "), doc$estado %||% "N/A"
        ),
        
        div(
          strong("🔢 Número: "), doc$numero %||% "Não informado",
          br(),
          strong("📊 Qualidade: "), paste0(round(doc$quality_score %||% 0), "%")
        ),
        
        if (!is.null(doc$url) && nchar(doc$url) > 0) {
          div(
            a("🔗 Documento original", 
              href = doc$url, 
              target = "_blank",
              class = "btn btn-link btn-sm p-0"
            )
          )
        }
      )
    })
    
    # ========================================================================
    # OUTPUTS - DOCUMENT CONTENT
    # ========================================================================
    
    output$document_content <- renderUI({
      if (is.null(values$processed_content)) {
        return(
          div(
            class = "no-document-selected text-center py-5",
            icon("file-alt", class = "fa-3x text-muted mb-3"),
            h4("Nenhum documento selecionado", class = "text-muted"),
            p("Selecione um documento na tabela de resultados para visualizar", class = "text-muted")
          )
        )
      }
      
      # Render content based on view mode
      switch(values$view_mode,
        "formatted" = render_formatted_content(values$processed_content, values$current_zoom),
        "raw" = render_raw_content(values$processed_content, values$current_zoom),
        "analysis" = render_analysis_content(values$processed_content, values$current_zoom)
      )
    })
    
    # ========================================================================
    # OUTPUTS - NAVIGATION AND ANNOTATIONS
    # ========================================================================
    
    output$has_sections <- reactive({
      !is.null(values$processed_content) && 
      !is.null(values$processed_content$sections) &&
      length(values$processed_content$sections) > 0
    })
    outputOptions(output, "has_sections", suspendWhenHidden = FALSE)
    
    output$has_annotations <- reactive({
      length(values$annotations) > 0
    })
    outputOptions(output, "has_annotations", suspendWhenHidden = FALSE)
    
    output$section_links <- renderUI({
      if (is.null(values$processed_content$sections)) {
        return(p("Seções não identificadas", class = "text-muted"))
      }
      
      sections <- values$processed_content$sections
      
      div(
        class = "section-links",
        lapply(seq_along(sections), function(i) {
          section <- sections[[i]]
          actionButton(
            paste0("goto_section_", i),
            paste0(i, ". ", str_trunc(section$title, 40)),
            class = "btn btn-link btn-sm d-block text-start",
            onclick = paste0("document.getElementById('section-", i, "').scrollIntoView({behavior: 'smooth'});")
          )
        })
      )
    })
    
    output$annotations_list <- renderUI({
      if (length(values$annotations) == 0) {
        return(p("Nenhuma anotação", class = "text-muted"))
      }
      
      div(
        class = "annotations-list",
        lapply(seq_along(values$annotations), function(i) {
          annotation <- values$annotations[[i]]
          div(
            class = "annotation-item mb-2 p-2 border rounded",
            style = paste0("border-left: 4px solid ", annotation$color, " !important;"),
            
            div(
              class = "d-flex justify-content-between align-items-start",
              
              div(
                strong(annotation$type),
                br(),
                span(str_trunc(annotation$text, 50), class = "text-muted")
              ),
              
              actionButton(
                paste0("delete_annotation_", i),
                "×",
                class = "btn btn-sm btn-outline-danger",
                style = "padding: 2px 6px; font-size: 12px;"
              )
            )
          )
        })
      )
    })
    
    # ========================================================================
    # EVENT HANDLERS - ZOOM CONTROLS
    # ========================================================================
    
    observeEvent(input$zoom_in, {
      current_index <- which(VIEWER_CONFIG$zoom_levels == values$current_zoom)
      if (current_index < length(VIEWER_CONFIG$zoom_levels)) {
        values$current_zoom <- VIEWER_CONFIG$zoom_levels[current_index + 1]
      }
    })
    
    observeEvent(input$zoom_out, {
      current_index <- which(VIEWER_CONFIG$zoom_levels == values$current_zoom)
      if (current_index > 1) {
        values$current_zoom <- VIEWER_CONFIG$zoom_levels[current_index - 1]
      }
    })
    
    # ========================================================================
    # EVENT HANDLERS - VIEW MODE
    # ========================================================================
    
    observeEvent(input$view_formatted, {
      values$view_mode <- "formatted"
    })
    
    observeEvent(input$view_raw, {
      values$view_mode <- "raw"
    })
    
    observeEvent(input$view_analysis, {
      values$view_mode <- "analysis"
    })
    
    # ========================================================================
    # EVENT HANDLERS - ANNOTATIONS
    # ========================================================================
    
    observeEvent(input$add_note, {
      # This would typically open a modal for note input
      showModal(modalDialog(
        title = "Adicionar Nota",
        
        textAreaInput(session$ns("note_text"), 
          "Texto da nota:",
          placeholder = "Digite sua anotação aqui...",
          rows = 4
        ),
        
        footer = tagList(
          modalButton("Cancelar"),
          actionButton(session$ns("save_note"), "Salvar", class = "btn-primary")
        )
      ))
    })
    
    observeEvent(input$save_note, {
      if (!is.null(input$note_text) && nchar(str_trim(input$note_text)) > 0) {
        new_annotation <- list(
          id = paste0("note_", length(values$annotations) + 1),
          type = "Nota",
          text = input$note_text,
          color = "#FFE066",
          timestamp = Sys.time(),
          position = NULL  # Would be set by text selection
        )
        
        values$annotations <- append(values$annotations, list(new_annotation))
        
        removeModal()
        
        showNotification("Nota adicionada com sucesso!", type = "success")
      }
    })
    
    observeEvent(input$clear_annotations, {
      values$annotations <- list()
      showNotification("Todas as anotações foram removidas", type = "message")
    })
    
    # ========================================================================
    # EVENT HANDLERS - DOCUMENT ACTIONS
    # ========================================================================
    
    observeEvent(input$print_document, {
      if (!is.null(values$processed_content)) {
        # Trigger browser print dialog
        session$sendCustomMessage("printDocument", list(
          title = values$processed_content$titulo,
          content = values$processed_content$content_html
        ))
      }
    })
    
    observeEvent(input$download_document, {
      if (!is.null(values$processed_content)) {
        # Prepare download
        session$sendCustomMessage("downloadDocument", list(
          filename = paste0(str_replace_all(values$processed_content$titulo, "[^\\w\\s-]", ""), ".html"),
          content = create_document_html_export(values$processed_content, values$annotations)
        ))
      }
    })
  })
}

#' Process document content for viewing
#' @param document Document data row
#' @return Processed document structure
process_document_content <- function(document) {
  
  log_event("Processing document content for viewer")
  
  # Extract and clean content
  title <- document$titulo %||% "Documento sem título"
  content <- document$ementa %||% ""
  
  # Basic content processing
  processed <- list(
    titulo = title,
    tipo = document$tipo,
    numero = document$numero,
    data = document$data,
    autor = document$autor,
    estado = document$estado,
    url = document$url,
    quality_score = document$quality_score,
    
    # Content processing
    content_raw = content,
    content_html = format_document_html(content),
    word_count = str_count(content, "\\S+"),
    char_count = nchar(content),
    
    # Document analysis
    readability = assess_document_readability(content),
    complexity = document$complexidade_estimada %||% "Não avaliada",
    category = document$categoria_primaria %||% "Não classificada",
    
    # Structure analysis
    sections = extract_document_sections(content),
    key_terms = extract_document_key_terms(content),
    
    # Metadata
    processed_at = Sys.time()
  )
  
  return(processed)
}

#' Format document content as HTML
#' @param content Raw document content
#' @return Formatted HTML
format_document_html <- function(content) {
  
  if (is.null(content) || nchar(str_trim(content)) == 0) {
    return("<p class='text-muted'>Conteúdo não disponível</p>")
  }
  
  # Basic HTML formatting
  formatted <- content %>%
    # Convert line breaks
    str_replace_all("\n", "<br>") %>%
    # Add paragraph structure
    str_replace_all("(<br>\\s*){2,}", "</p><p>") %>%
    # Wrap in paragraph tags
    paste0("<p>", ., "</p>") %>%
    # Clean up empty paragraphs
    str_replace_all("<p>\\s*</p>", "") %>%
    # Format common legal patterns
    format_legal_patterns()
  
  return(formatted)
}

#' Format common legal document patterns
#' @param html HTML content
#' @return Enhanced HTML with legal formatting
format_legal_patterns <- function(html) {
  
  formatted <- html %>%
    # Article numbers
    str_replace_all("\\b(Art\\.?\\s*\\d+)", "<strong class='article-number'>\\1</strong>") %>%
    # Paragraph symbols
    str_replace_all("§\\s*(\\d+)", "<strong class='paragraph-symbol'>§ \\1</strong>") %>%
    # Roman numerals
    str_replace_all("\\b([IVX]+)\\s*-", "<strong class='roman-numeral'>\\1</strong> -") %>%
    # Legal references
    str_replace_all("\\b(Lei\\s+n[º°]?\\s*[\\d\\.]+)", "<em class='legal-reference'>\\1</em>") %>%
    str_replace_all("\\b(Decreto\\s+n[º°]?\\s*[\\d\\.]+)", "<em class='legal-reference'>\\1</em>")
  
  return(formatted)
}

#' Extract document sections
#' @param content Document content
#' @return List of sections
extract_document_sections <- function(content) {
  
  if (is.null(content) || nchar(str_trim(content)) == 0) {
    return(NULL)
  }
  
  # Simple section detection based on common patterns
  section_patterns <- c(
    "CAPÍTULO\\s+[IVX]+",
    "SEÇÃO\\s+[IVX]+", 
    "Art\\.?\\s*\\d+",
    "§\\s*\\d+"
  )
  
  sections <- list()
  
  for (pattern in section_patterns) {
    matches <- str_locate_all(content, pattern)[[1]]
    
    if (nrow(matches) > 0) {
      for (i in 1:nrow(matches)) {
        start <- matches[i, 1]
        
        # Extract title (next 50 characters)
        title_end <- min(start + 50, nchar(content))
        title <- str_sub(content, start, title_end)
        title <- str_split(title, "\\.|\\n")[[1]][1]
        
        sections <- append(sections, list(list(
          title = str_trim(title),
          start_pos = start,
          pattern = pattern
        )))
      }
    }
  }
  
  # Sort by position and remove duplicates
  if (length(sections) > 0) {
    sections <- sections[order(sapply(sections, function(x) x$start_pos))]
    # Keep only first 10 sections to avoid clutter
    sections <- head(sections, 10)
  }
  
  return(sections)
}

#' Extract key terms from document
#' @param content Document content
#' @return Vector of key terms
extract_document_key_terms <- function(content) {
  
  if (is.null(content) || nchar(str_trim(content)) == 0) {
    return(character(0))
  }
  
  # Transport-related key terms
  transport_terms <- c(
    "transporte", "mobilidade", "trânsito", "viário", "rodoviário",
    "ônibus", "metrô", "trem", "bicicleta", "pedestre",
    "estacionamento", "semáforo", "sinalização", "via", "avenida"
  )
  
  content_lower <- str_to_lower(content)
  found_terms <- transport_terms[sapply(transport_terms, function(term) {
    str_detect(content_lower, term)
  })]
  
  return(found_terms)
}

#' Assess document readability
#' @param content Document content
#' @return Readability assessment
assess_document_readability <- function(content) {
  
  if (is.null(content) || nchar(str_trim(content)) == 0) {
    return("Não avaliável")
  }
  
  # Simple readability metrics
  word_count <- str_count(content, "\\S+")
  sentence_count <- str_count(content, "[.!?]+")
  
  if (sentence_count == 0) sentence_count <- 1
  
  avg_words_per_sentence <- word_count / sentence_count
  
  # Classification
  if (avg_words_per_sentence <= 15) return("Fácil")
  if (avg_words_per_sentence <= 25) return("Moderada")
  if (avg_words_per_sentence <= 35) return("Difícil")
  return("Muito Difícil")
}

#' Render formatted content view
#' @param doc Processed document
#' @param zoom Zoom level
#' @return HTML content
render_formatted_content <- function(doc, zoom) {
  
  div(
    class = "formatted-content",
    style = paste0("padding: 20px; font-size: ", zoom, "em; line-height: 1.6;"),
    
    # Document header
    div(
      class = "document-header mb-4 pb-3 border-bottom",
      h3(doc$titulo, class = "mb-2"),
      div(
        class = "document-meta text-muted",
        span(doc$tipo, class = "me-3"),
        span(paste("Nº", doc$numero), class = "me-3"),
        span(format(as.Date(doc$data), "%d/%m/%Y"))
      )
    ),
    
    # Document content
    div(
      class = "document-body",
      HTML(doc$content_html)
    ),
    
    # Document footer with statistics
    div(
      class = "document-footer mt-4 pt-3 border-top",
      div(
        class = "row text-muted",
        div(
          class = "col-md-4",
          small(paste("Palavras:", doc$word_count))
        ),
        div(
          class = "col-md-4", 
          small(paste("Legibilidade:", doc$readability))
        ),
        div(
          class = "col-md-4",
          small(paste("Qualidade:", round(doc$quality_score %||% 0), "%"))
        )
      )
    )
  )
}

#' Render raw content view
#' @param doc Processed document
#' @param zoom Zoom level
#' @return HTML content
render_raw_content <- function(doc, zoom) {
  
  div(
    class = "raw-content",
    style = paste0("padding: 20px; font-size: ", zoom, "em;"),
    
    h5("Texto Original", class = "mb-3"),
    
    pre(
      class = "raw-text",
      style = "background: #f8f9fa; padding: 15px; border-radius: 8px; white-space: pre-wrap; font-family: 'Courier New', monospace;",
      doc$content_raw
    )
  )
}

#' Render analysis content view
#' @param doc Processed document  
#' @param zoom Zoom level
#' @return HTML content
render_analysis_content <- function(doc, zoom) {
  
  div(
    class = "analysis-content",
    style = paste0("padding: 20px; font-size: ", zoom, "em;"),
    
    h5("Análise do Documento", class = "mb-4"),
    
    # Statistics panel
    div(
      class = "row mb-4",
      
      div(
        class = "col-md-3",
        div(
          class = "stat-card text-center p-3 border rounded",
          h4(doc$word_count, class = "mb-1 text-primary"),
          small("Palavras", class = "text-muted")
        )
      ),
      
      div(
        class = "col-md-3",
        div(
          class = "stat-card text-center p-3 border rounded",
          h4(doc$char_count, class = "mb-1 text-info"),
          small("Caracteres", class = "text-muted")
        )
      ),
      
      div(
        class = "col-md-3",
        div(
          class = "stat-card text-center p-3 border rounded",
          h4(doc$readability, class = "mb-1 text-success"),
          small("Legibilidade", class = "text-muted")
        )
      ),
      
      div(
        class = "col-md-3",
        div(
          class = "stat-card text-center p-3 border rounded",
          h4(paste0(round(doc$quality_score %||% 0), "%"), class = "mb-1 text-warning"),
          small("Qualidade", class = "text-muted")
        )
      )
    ),
    
    # Analysis details
    div(
      class = "row",
      
      div(
        class = "col-md-6",
        h6("Classificação"),
        p(strong("Categoria: "), doc$category),
        p(strong("Complexidade: "), doc$complexity),
        
        if (length(doc$key_terms) > 0) {
          tagList(
            h6("Termos-chave identificados"),
            div(
              class = "key-terms",
              lapply(doc$key_terms, function(term) {
                span(term, class = "badge bg-secondary me-1")
              })
            )
          )
        }
      ),
      
      div(
        class = "col-md-6",
        h6("Estrutura do Documento"),
        
        if (!is.null(doc$sections) && length(doc$sections) > 0) {
          div(
            class = "sections-list",
            p(paste("Seções identificadas:", length(doc$sections))),
            div(
              class = "list-group list-group-flush",
              lapply(seq_along(doc$sections), function(i) {
                section <- doc$sections[[i]]
                div(
                  class = "list-group-item px-0",
                  small(paste0(i, ". ", section$title))
                )
              })
            )
          )
        } else {
          p("Estrutura não identificada", class = "text-muted")
        }
      )
    )
  )
}

#' Create HTML export of document with annotations
#' @param doc Processed document
#' @param annotations List of annotations
#' @return Complete HTML for export
create_document_html_export <- function(doc, annotations = list()) {
  
  paste0(
    "<!DOCTYPE html>",
    "<html lang='pt-BR'>",
    "<head>",
    "<meta charset='UTF-8'>",
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
    "<title>", htmltools::htmlEscape(doc$titulo), "</title>",
    "<style>",
    "body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }",
    ".document-header { border-bottom: 2px solid #ddd; padding-bottom: 15px; margin-bottom: 20px; }",
    ".document-meta { color: #666; font-size: 0.9em; }",
    ".document-body { line-height: 1.6; }",
    ".annotation { background: #fffacd; padding: 2px 4px; border-radius: 3px; }",
    "</style>",
    "</head>",
    "<body>",
    "<div class='document-header'>",
    "<h1>", htmltools::htmlEscape(doc$titulo), "</h1>",
    "<div class='document-meta'>",
    "<p>", doc$tipo, " - Nº ", doc$numero, " - ", format(as.Date(doc$data), "%d/%m/%Y"), "</p>",
    "</div>",
    "</div>",
    "<div class='document-body'>",
    doc$content_html,
    "</div>",
    "</body>",
    "</html>"
  )
}

#' Helper function for string truncation
str_trunc <- function(string, width) {
  if (is.na(string) || nchar(string) <= width) {
    return(string)
  }
  paste0(substr(string, 1, width - 3), "...")
}