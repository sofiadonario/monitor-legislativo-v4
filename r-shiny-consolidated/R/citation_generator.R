# Academic Citation Generation System for Monitor Legislativo v4
# Generate citations in multiple academic formats for legislative documents

library(shiny)
library(htmltools)
library(dplyr)
library(stringr)
library(jsonlite)
library(lubridate)

# Citation configuration
CITATION_CONFIG <- list(
  formats = list(
    "ABNT" = "Associação Brasileira de Normas Técnicas",
    "APA" = "American Psychological Association", 
    "Chicago" = "Chicago Manual of Style",
    "MLA" = "Modern Language Association",
    "Vancouver" = "Vancouver Style",
    "Harvard" = "Harvard Referencing",
    "NBR6023" = "ABNT NBR 6023:2018"
  ),
  
  document_types = list(
    "Lei" = "legislation",
    "Decreto" = "decree",
    "Resolução" = "resolution",
    "Portaria" = "ordinance",
    "Instrução Normativa" = "normative_instruction",
    "Medida Provisória" = "provisional_measure"
  ),
  
  citation_elements = list(
    "author" = "Autor/Instituição",
    "title" = "Título",
    "type" = "Tipo de Documento",
    "number" = "Número",
    "date" = "Data",
    "source" = "Fonte",
    "url" = "URL",
    "access_date" = "Data de Acesso"
  )
)

#' Create citation generator interface
#' @param id Module ID
#' @return Citation generator UI
citation_generator_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "citation-generator-container",
    
    # Header
    div(
      class = "citation-header",
      style = "background: #f8f9fa; padding: 15px; border-radius: 8px 8px 0 0; border-bottom: 1px solid #dee2e6;",
      
      fluidRow(
        column(8,
          h4("🎓 Gerador de Citações Acadêmicas", style = "margin: 0; color: #2c3e50;")
        ),
        
        column(4,
          div(
            class = "citation-controls text-end",
            
            # Format selector
            selectInput(
              ns("citation_format"),
              NULL,
              choices = CITATION_CONFIG$formats,
              selected = "ABNT",
              width = "200px"
            )
          )
        )
      )
    ),
    
    # Document selection area
    div(
      class = "document-selection-area",
      style = "background: #ffffff; padding: 15px; border-bottom: 1px solid #dee2e6;",
      
      h6("📄 Documentos para Citar", class = "mb-3"),
      
      # Document selector or current document display
      conditionalPanel(
        condition = paste0("output['", ns("has_documents"), "']"),
        
        div(
          class = "documents-to-cite",
          
          # Checkbox group for multiple documents
          checkboxGroupInput(
            ns("selected_documents"),
            "Selecione os documentos:",
            choices = NULL,
            width = "100%"
          ),
          
          # Select all/none buttons
          div(
            class = "selection-controls mt-2",
            actionButton(
              ns("select_all"),
              "Selecionar Todos",
              class = "btn btn-sm btn-outline-primary"
            ),
            actionButton(
              ns("select_none"),
              "Desmarcar Todos",
              class = "btn btn-sm btn-outline-secondary ms-2"
            )
          )
        )
      ),
      
      conditionalPanel(
        condition = paste0("!output['", ns("has_documents"), "']"),
        p("Nenhum documento disponível para citação", class = "text-muted")
      )
    ),
    
    # Citation options
    div(
      class = "citation-options",
      style = "background: #f8f9fa; padding: 15px;",
      
      h6("⚙️ Opções de Citação", class = "mb-3"),
      
      fluidRow(
        column(6,
          checkboxInput(
            ns("include_url"),
            "Incluir URL do documento",
            value = TRUE
          ),
          
          checkboxInput(
            ns("include_access_date"),
            "Incluir data de acesso",
            value = TRUE
          ),
          
          checkboxInput(
            ns("abbreviate_authors"),
            "Abreviar nomes de autores",
            value = FALSE
          )
        ),
        
        column(6,
          checkboxInput(
            ns("group_by_type"),
            "Agrupar por tipo de documento",
            value = TRUE
          ),
          
          checkboxInput(
            ns("sort_chronologically"),
            "Ordenar cronologicamente",
            value = TRUE
          ),
          
          checkboxInput(
            ns("include_abstracts"),
            "Incluir ementas (quando disponível)",
            value = FALSE
          )
        )
      ),
      
      # Generate button
      div(
        class = "text-center mt-3",
        actionButton(
          ns("generate_citations"),
          "📝 Gerar Citações",
          class = "btn btn-success btn-lg"
        )
      )
    ),
    
    # Generated citations area
    div(
      class = "generated-citations-area",
      style = "background: white; min-height: 200px;",
      
      conditionalPanel(
        condition = paste0("output['", ns("citations_ready"), "']"),
        
        # Citation display tabs
        navset_card_tab(
          id = ns("citation_tabs"),
          
          nav_panel(
            "📝 Citações Individuais",
            div(
              class = "individual-citations p-3",
              
              # Copy all button
              div(
                class = "mb-3 text-end",
                actionButton(
                  ns("copy_all_individual"),
                  "📋 Copiar Todas",
                  class = "btn btn-sm btn-outline-primary"
                )
              ),
              
              # Individual citations list
              uiOutput(ns("individual_citations"))
            )
          ),
          
          nav_panel(
            "📚 Lista de Referências",
            div(
              class = "reference-list p-3",
              
              # Copy button
              div(
                class = "mb-3 text-end",
                actionButton(
                  ns("copy_reference_list"),
                  "📋 Copiar Lista",
                  class = "btn btn-sm btn-outline-primary"
                )
              ),
              
              # Reference list
              div(
                class = "reference-list-content",
                style = "background: #f8f9fa; padding: 15px; border-radius: 8px; font-family: 'Times New Roman', serif;",
                uiOutput(ns("reference_list"))
              )
            )
          ),
          
          nav_panel(
            "💾 Exportar",
            div(
              class = "export-options p-3",
              
              h6("Formato de Exportação"),
              
              radioButtons(
                ns("export_format"),
                NULL,
                choices = c(
                  "Texto Simples (.txt)" = "txt",
                  "Rich Text Format (.rtf)" = "rtf",
                  "BibTeX (.bib)" = "bibtex",
                  "RIS (.ris)" = "ris",
                  "JSON (.json)" = "json"
                ),
                selected = "txt"
              ),
              
              # Additional export options
              checkboxInput(
                ns("include_metadata"),
                "Incluir metadados completos",
                value = FALSE
              ),
              
              # Export button
              div(
                class = "text-center mt-3",
                downloadButton(
                  ns("export_citations"),
                  "💾 Baixar Citações",
                  class = "btn btn-primary"
                )
              )
            )
          ),
          
          nav_panel(
            "ℹ️ Guia de Citação",
            div(
              class = "citation-guide p-3",
              uiOutput(ns("citation_guide"))
            )
          )
        )
      ),
      
      conditionalPanel(
        condition = paste0("!output['", ns("citations_ready"), "']"),
        div(
          class = "no-citations-state text-center py-5",
          icon("graduation-cap", class = "fa-3x text-muted mb-3"),
          h4("Gerador de Citações", class = "text-muted"),
          p("Selecione documentos e clique em 'Gerar Citações' para criar referências acadêmicas", class = "text-muted")
        )
      )
    )
  )
}

#' Citation generator server function
#' @param id Module ID
#' @param documents Reactive containing available documents
citation_generator_server <- function(id, documents) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values
    values <- reactiveValues(
      generated_citations = NULL,
      selected_docs = NULL
    )
    
    # ========================================================================
    # DOCUMENT SELECTION
    # ========================================================================
    
    output$has_documents <- reactive({
      !is.null(documents()) && nrow(documents()) > 0
    })
    outputOptions(output, "has_documents", suspendWhenHidden = FALSE)
    
    # Update document choices
    observe({
      if (!is.null(documents()) && nrow(documents()) > 0) {
        docs <- documents()
        
        # Create choices with document info
        choices <- setNames(
          1:nrow(docs),
          paste0(
            str_trunc(docs$titulo, 60), 
            " (", docs$tipo, " - ", 
            format(as.Date(docs$data), "%Y"), ")"
          )
        )
        
        updateCheckboxGroupInput(
          session, "selected_documents",
          choices = choices,
          selected = if (nrow(docs) == 1) 1 else NULL
        )
      }
    })
    
    # Select all documents
    observeEvent(input$select_all, {
      if (!is.null(documents()) && nrow(documents()) > 0) {
        updateCheckboxGroupInput(
          session, "selected_documents",
          selected = 1:nrow(documents())
        )
      }
    })
    
    # Deselect all documents
    observeEvent(input$select_none, {
      updateCheckboxGroupInput(
        session, "selected_documents",
        selected = character(0)
      )
    })
    
    # ========================================================================
    # CITATION GENERATION
    # ========================================================================
    
    observeEvent(input$generate_citations, {
      if (is.null(input$selected_documents) || length(input$selected_documents) == 0) {
        showNotification("Selecione pelo menos um documento para citar", type = "warning")
        return()
      }
      
      # Get selected documents
      selected_indices <- as.numeric(input$selected_documents)
      values$selected_docs <- documents()[selected_indices, ]
      
      # Generate citations based on format
      citations <- generate_citations(
        documents = values$selected_docs,
        format = input$citation_format,
        options = list(
          include_url = input$include_url,
          include_access_date = input$include_access_date,
          abbreviate_authors = input$abbreviate_authors,
          group_by_type = input$group_by_type,
          sort_chronologically = input$sort_chronologically,
          include_abstracts = input$include_abstracts
        )
      )
      
      values$generated_citations <- citations
      
      showNotification("Citações geradas com sucesso!", type = "success")
    })
    
    # ========================================================================
    # OUTPUTS
    # ========================================================================
    
    output$citations_ready <- reactive({
      !is.null(values$generated_citations)
    })
    outputOptions(output, "citations_ready", suspendWhenHidden = FALSE)
    
    # Individual citations
    output$individual_citations <- renderUI({
      if (is.null(values$generated_citations)) return(NULL)
      
      citations <- values$generated_citations$individual
      
      div(
        class = "citations-list",
        lapply(seq_along(citations), function(i) {
          citation <- citations[[i]]
          doc <- values$selected_docs[i, ]
          
          div(
            class = "citation-item mb-4 p-3 border rounded",
            style = "background: #f8f9fa;",
            
            # Document title
            h6(str_trunc(doc$titulo, 60), class = "text-primary mb-2"),
            
            # Citation text
            div(
              class = "citation-text",
              style = "font-family: 'Times New Roman', serif; line-height: 1.6;",
              p(citation$formatted, class = "mb-2")
            ),
            
            # Copy button
            div(
              class = "citation-actions",
              actionButton(
                paste0("copy_citation_", i),
                "📋 Copiar",
                class = "btn btn-sm btn-outline-secondary",
                onclick = paste0("navigator.clipboard.writeText('", 
                               gsub("'", "\\'", citation$formatted, fixed = TRUE), 
                               "'); $(this).text('✓ Copiado!').delay(2000).queue(function(){ $(this).text('📋 Copiar').dequeue(); });")
              )
            )
          )
        })
      )
    })
    
    # Reference list
    output$reference_list <- renderUI({
      if (is.null(values$generated_citations)) return(NULL)
      
      references <- values$generated_citations$reference_list
      
      if (input$group_by_type && !is.null(references$grouped)) {
        # Grouped by type
        div(
          lapply(names(references$grouped), function(type) {
            group <- references$grouped[[type]]
            
            div(
              class = "reference-group mb-4",
              
              h6(type, class = "text-uppercase text-muted mb-2"),
              
              div(
                class = "references",
                lapply(group, function(ref) {
                  p(ref, style = "text-indent: -2em; padding-left: 2em; margin-bottom: 0.5em;")
                })
              )
            )
          })
        )
      } else {
        # Ungrouped list
        div(
          class = "references",
          lapply(references$ungrouped, function(ref) {
            p(ref, style = "text-indent: -2em; padding-left: 2em; margin-bottom: 0.5em;")
          })
        )
      }
    })
    
    # Citation guide
    output$citation_guide <- renderUI({
      format_name <- names(CITATION_CONFIG$formats)[which(CITATION_CONFIG$formats == input$citation_format)]
      
      div(
        h5(paste("📖 Guia de Citação -", format_name), class = "mb-3"),
        
        create_citation_guide(input$citation_format)
      )
    })
    
    # ========================================================================
    # COPY FUNCTIONS
    # ========================================================================
    
    observeEvent(input$copy_all_individual, {
      if (!is.null(values$generated_citations)) {
        all_citations <- paste(
          sapply(values$generated_citations$individual, function(c) c$formatted),
          collapse = "\n\n"
        )
        
        session$sendCustomMessage("copyToClipboard", all_citations)
        showNotification("Todas as citações copiadas!", type = "success")
      }
    })
    
    observeEvent(input$copy_reference_list, {
      if (!is.null(values$generated_citations)) {
        refs <- values$generated_citations$reference_list
        
        if (input$group_by_type && !is.null(refs$grouped)) {
          # Format grouped references
          all_refs <- paste(
            sapply(names(refs$grouped), function(type) {
              paste(
                type, "\n",
                paste(refs$grouped[[type]], collapse = "\n"),
                "\n"
              )
            }),
            collapse = "\n"
          )
        } else {
          all_refs <- paste(refs$ungrouped, collapse = "\n")
        }
        
        session$sendCustomMessage("copyToClipboard", all_refs)
        showNotification("Lista de referências copiada!", type = "success")
      }
    })
    
    # ========================================================================
    # EXPORT FUNCTIONALITY
    # ========================================================================
    
    output$export_citations <- downloadHandler(
      filename = function() {
        paste0("citacoes_", Sys.Date(), ".", input$export_format)
      },
      
      content = function(file) {
        if (is.null(values$generated_citations)) {
          return()
        }
        
        export_content <- export_citations(
          citations = values$generated_citations,
          documents = values$selected_docs,
          format = input$export_format,
          citation_style = input$citation_format,
          include_metadata = input$include_metadata
        )
        
        if (input$export_format %in% c("txt", "bib", "ris")) {
          writeLines(export_content, file)
        } else if (input$export_format == "json") {
          write_json(export_content, file, pretty = TRUE)
        } else if (input$export_format == "rtf") {
          # For RTF, would need additional processing
          writeLines(export_content, file)
        }
      }
    )
  })
}

#' Generate citations for documents
#' @param documents Data frame of documents to cite
#' @param format Citation format
#' @param options Citation options
#' @return List with individual citations and reference list
generate_citations <- function(documents, format, options) {
  
  log_event(paste("Generating citations in", format, "format for", nrow(documents), "documents"))
  
  # Sort documents if requested
  if (options$sort_chronologically) {
    documents <- documents %>% 
      arrange(desc(as.Date(data)))
  }
  
  # Generate individual citations
  individual_citations <- lapply(1:nrow(documents), function(i) {
    doc <- documents[i, ]
    
    citation <- switch(format,
      "ABNT" = format_citation_abnt(doc, options),
      "APA" = format_citation_apa(doc, options),
      "Chicago" = format_citation_chicago(doc, options),
      "MLA" = format_citation_mla(doc, options),
      "Vancouver" = format_citation_vancouver(doc, options),
      "Harvard" = format_citation_harvard(doc, options),
      "NBR6023" = format_citation_nbr6023(doc, options),
      format_citation_abnt(doc, options)  # Default to ABNT
    )
    
    list(
      formatted = citation,
      document_id = i,
      document_title = doc$titulo
    )
  })
  
  # Generate reference list
  reference_list <- create_reference_list(individual_citations, documents, format, options)
  
  return(list(
    individual = individual_citations,
    reference_list = reference_list,
    format = format,
    generated_at = Sys.time()
  ))
}

#' Format citation in ABNT style
#' @param doc Document data
#' @param options Citation options
#' @return Formatted citation string
format_citation_abnt <- function(doc, options) {
  
  # Determine author/institution
  author <- if (!is.null(doc$autor) && !is.na(doc$autor) && nchar(doc$autor) > 0) {
    format_author_abnt(doc$autor, options$abbreviate_authors)
  } else {
    determine_institution_abnt(doc$estado, doc$tipo)
  }
  
  # Document title
  title <- toupper(doc$titulo)
  
  # Document type and number
  type_number <- paste(doc$tipo, "nº", doc$numero)
  
  # Date
  date_str <- format(as.Date(doc$data), "%d de %B de %Y")
  
  # Basic citation
  citation <- paste0(author, ". ", title, ". ", type_number, ", ", date_str, ".")
  
  # Add URL if requested
  if (options$include_url && !is.null(doc$url) && !is.na(doc$url)) {
    citation <- paste0(citation, " Disponível em: <", doc$url, ">.")
    
    if (options$include_access_date) {
      access_date <- format(Sys.Date(), "%d %b. %Y")
      citation <- paste0(citation, " Acesso em: ", access_date, ".")
    }
  }
  
  return(citation)
}

#' Format citation in APA style
#' @param doc Document data
#' @param options Citation options
#' @return Formatted citation string
format_citation_apa <- function(doc, options) {
  
  # Author/institution
  author <- if (!is.null(doc$autor) && !is.na(doc$autor) && nchar(doc$autor) > 0) {
    format_author_apa(doc$autor, options$abbreviate_authors)
  } else {
    determine_institution_apa(doc$estado, doc$tipo)
  }
  
  # Year
  year <- format(as.Date(doc$data), "%Y")
  
  # Title (italicized in APA)
  title <- paste0("_", doc$titulo, "_")
  
  # Document info
  doc_info <- paste0("(", doc$tipo, " nº ", doc$numero, ")")
  
  # Basic citation
  citation <- paste0(author, " (", year, "). ", title, " ", doc_info, ".")
  
  # Add URL if requested
  if (options$include_url && !is.null(doc$url) && !is.na(doc$url)) {
    citation <- paste0(citation, " Retrieved from ", doc$url)
    
    if (options$include_access_date) {
      # APA 7th edition doesn't require access date unless content changes
      # But include if specifically requested
      access_date <- format(Sys.Date(), "%B %d, %Y")
      citation <- paste0(citation, " (accessed ", access_date, ")")
    }
  }
  
  return(citation)
}

#' Format citation in Chicago style
#' @param doc Document data
#' @param options Citation options
#' @return Formatted citation string
format_citation_chicago <- function(doc, options) {
  
  # Author/institution
  author <- if (!is.null(doc$autor) && !is.na(doc$autor) && nchar(doc$autor) > 0) {
    format_author_chicago(doc$autor, options$abbreviate_authors)
  } else {
    determine_institution_chicago(doc$estado, doc$tipo)
  }
  
  # Title (quoted in Chicago for legislation)
  title <- paste0('"', doc$titulo, '"')
  
  # Document type and number
  type_number <- paste(doc$tipo, "nº", doc$numero)
  
  # Date
  date_str <- format(as.Date(doc$data), "%B %d, %Y")
  
  # Basic citation
  citation <- paste0(author, ". ", title, ". ", type_number, ". ", date_str, ".")
  
  # Add URL if requested
  if (options$include_url && !is.null(doc$url) && !is.na(doc$url)) {
    citation <- paste0(citation, " ", doc$url)
    
    if (options$include_access_date) {
      access_date <- format(Sys.Date(), "%B %d, %Y")
      citation <- paste0(citation, " (accessed ", access_date, ")")
    }
  }
  
  return(citation)
}

#' Format citation in MLA style
#' @param doc Document data
#' @param options Citation options
#' @return Formatted citation string
format_citation_mla <- function(doc, options) {
  
  # Author/institution
  author <- if (!is.null(doc$autor) && !is.na(doc$autor) && nchar(doc$autor) > 0) {
    format_author_mla(doc$autor)
  } else {
    determine_institution_mla(doc$estado, doc$tipo)
  }
  
  # Title (quoted)
  title <- paste0('"', doc$titulo, '."')
  
  # Document type and number
  type_number <- paste(doc$tipo, "nº", doc$numero)
  
  # Date
  date_str <- format(as.Date(doc$data), "%d %b. %Y")
  
  # Basic citation
  citation <- paste0(author, ". ", title, " ", type_number, ", ", date_str)
  
  # Add URL if requested (MLA uses "Web" medium)
  if (options$include_url && !is.null(doc$url) && !is.na(doc$url)) {
    citation <- paste0(citation, ". Web")
    
    if (options$include_access_date) {
      access_date <- format(Sys.Date(), "%d %b. %Y")
      citation <- paste0(citation, ". ", access_date)
    }
  }
  
  citation <- paste0(citation, ".")
  
  return(citation)
}

#' Format citation in Vancouver style
#' @param doc Document data
#' @param options Citation options
#' @return Formatted citation string
format_citation_vancouver <- function(doc, options) {
  
  # Author/institution (abbreviated in Vancouver)
  author <- if (!is.null(doc$autor) && !is.na(doc$autor) && nchar(doc$autor) > 0) {
    format_author_vancouver(doc$autor)
  } else {
    determine_institution_vancouver(doc$estado, doc$tipo)
  }
  
  # Title
  title <- doc$titulo
  
  # Document info
  doc_info <- paste0(doc$tipo, " nº ", doc$numero)
  
  # Date
  date_str <- format(as.Date(doc$data), "%Y %b %d")
  
  # Basic citation
  citation <- paste0(author, ". ", title, ". ", doc_info, ". ", date_str)
  
  # Add URL if requested
  if (options$include_url && !is.null(doc$url) && !is.na(doc$url)) {
    citation <- paste0(citation, ". Available from: ", doc$url)
    
    if (options$include_access_date) {
      access_date <- format(Sys.Date(), "%Y %b %d")
      citation <- paste0(citation, " [cited ", access_date, "]")
    }
  }
  
  citation <- paste0(citation, ".")
  
  return(citation)
}

#' Format citation in Harvard style
#' @param doc Document data
#' @param options Citation options
#' @return Formatted citation string
format_citation_harvard <- function(doc, options) {
  
  # Author/institution
  author <- if (!is.null(doc$autor) && !is.na(doc$autor) && nchar(doc$autor) > 0) {
    format_author_harvard(doc$autor, options$abbreviate_authors)
  } else {
    determine_institution_harvard(doc$estado, doc$tipo)
  }
  
  # Year
  year <- format(as.Date(doc$data), "%Y")
  
  # Title (italicized)
  title <- paste0("_", doc$titulo, "_")
  
  # Document info
  doc_info <- paste0(doc$tipo, " nº ", doc$numero)
  
  # Basic citation
  citation <- paste0(author, " ", year, ", ", title, ", ", doc_info)
  
  # Add URL if requested
  if (options$include_url && !is.null(doc$url) && !is.na(doc$url)) {
    citation <- paste0(citation, ", viewed ", format(Sys.Date(), "%d %B %Y"), ", <", doc$url, ">")
  }
  
  citation <- paste0(citation, ".")
  
  return(citation)
}

#' Format citation in NBR 6023:2018 style
#' @param doc Document data
#' @param options Citation options
#' @return Formatted citation string
format_citation_nbr6023 <- function(doc, options) {
  # NBR 6023:2018 is the updated ABNT standard
  # Similar to ABNT but with some specific requirements
  
  # Jurisdiction (in uppercase)
  jurisdiction <- determine_jurisdiction_nbr6023(doc$estado, doc$tipo)
  
  # Document identification
  doc_id <- paste(doc$tipo, "nº", doc$numero, "de", format(as.Date(doc$data), "%d de %B de %Y"))
  
  # Title (only first letter capitalized unless proper noun)
  title <- str_to_sentence(doc$titulo)
  
  # Basic citation
  citation <- paste0(jurisdiction, ". ", doc_id, ". ", title, ".")
  
  # Publisher info
  if (!is.null(doc$fonte) && !is.na(doc$fonte)) {
    citation <- paste0(citation, " ", doc$fonte, ".")
  }
  
  # Add URL if requested
  if (options$include_url && !is.null(doc$url) && !is.na(doc$url)) {
    citation <- paste0(citation, " Disponível em: ", doc$url, ".")
    
    if (options$include_access_date) {
      access_date <- format(Sys.Date(), "%d %b. %Y")
      citation <- paste0(citation, " Acesso em: ", access_date, ".")
    }
  }
  
  return(citation)
}

#' Helper functions for author formatting
format_author_abnt <- function(author, abbreviate = FALSE) {
  if (abbreviate) {
    # Last name, First initials
    parts <- str_split(author, " ")[[1]]
    if (length(parts) > 1) {
      last_name <- toupper(parts[length(parts)])
      initials <- paste0(substr(parts[-length(parts)], 1, 1), ".", collapse = " ")
      return(paste0(last_name, ", ", initials))
    }
  }
  return(toupper(author))
}

format_author_apa <- function(author, abbreviate = FALSE) {
  parts <- str_split(author, " ")[[1]]
  if (length(parts) > 1) {
    last_name <- parts[length(parts)]
    initials <- paste0(substr(parts[-length(parts)], 1, 1), ".", collapse = " ")
    return(paste0(last_name, ", ", initials))
  }
  return(author)
}

format_author_chicago <- function(author, abbreviate = FALSE) {
  # Chicago uses full names in bibliography
  return(author)
}

format_author_mla <- function(author) {
  parts <- str_split(author, " ")[[1]]
  if (length(parts) > 1) {
    last_name <- parts[length(parts)]
    first_names <- paste(parts[-length(parts)], collapse = " ")
    return(paste0(last_name, ", ", first_names))
  }
  return(author)
}

format_author_vancouver <- function(author) {
  parts <- str_split(author, " ")[[1]]
  if (length(parts) > 1) {
    last_name <- parts[length(parts)]
    initials <- paste0(substr(parts[-length(parts)], 1, 1), collapse = "")
    return(paste0(last_name, " ", initials))
  }
  return(author)
}

format_author_harvard <- function(author, abbreviate = FALSE) {
  # Similar to APA
  return(format_author_apa(author, abbreviate))
}

#' Helper functions for institution determination
determine_institution_abnt <- function(state, doc_type) {
  if (!is.null(state) && !is.na(state)) {
    return(paste0(toupper(state), ". ", get_state_name(state)))
  }
  return("BRASIL")
}

determine_institution_apa <- function(state, doc_type) {
  if (!is.null(state) && !is.na(state)) {
    return(paste0(get_state_name(state), " State"))
  }
  return("Brazil")
}

determine_institution_chicago <- function(state, doc_type) {
  if (!is.null(state) && !is.na(state)) {
    return(paste0(get_state_name(state), ", Brazil"))
  }
  return("Brazil")
}

determine_institution_mla <- function(state, doc_type) {
  if (!is.null(state) && !is.na(state)) {
    return(get_state_name(state))
  }
  return("Brazil")
}

determine_institution_vancouver <- function(state, doc_type) {
  if (!is.null(state) && !is.na(state)) {
    return(paste0(state, " State"))
  }
  return("Brazil")
}

determine_institution_harvard <- function(state, doc_type) {
  if (!is.null(state) && !is.na(state)) {
    return(get_state_name(state))
  }
  return("Brazil")
}

determine_jurisdiction_nbr6023 <- function(state, doc_type) {
  if (!is.null(state) && !is.na(state)) {
    state_name <- get_state_name(state)
    return(toupper(paste0(state, " (Estado). ", state_name)))
  }
  return("BRASIL")
}

#' Get full state name from abbreviation
get_state_name <- function(state_abbr) {
  state_names <- list(
    "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
    "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", "ES" = "Espírito Santo",
    "GO" = "Goiás", "MA" = "Maranhão", "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul",
    "MG" = "Minas Gerais", "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná",
    "PE" = "Pernambuco", "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
    "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima", "SC" = "Santa Catarina",
    "SP" = "São Paulo", "SE" = "Sergipe", "TO" = "Tocantins"
  )
  
  return(state_names[[state_abbr]] %||% state_abbr)
}

#' Create reference list from individual citations
#' @param citations Individual citations
#' @param documents Original documents
#' @param format Citation format
#' @param options Citation options
#' @return Reference list structure
create_reference_list <- function(citations, documents, format, options) {
  
  # Extract formatted citations
  formatted_citations <- sapply(citations, function(c) c$formatted)
  
  # Sort alphabetically (most formats require this)
  sorted_indices <- order(formatted_citations)
  sorted_citations <- formatted_citations[sorted_indices]
  sorted_docs <- documents[sorted_indices, ]
  
  if (options$group_by_type) {
    # Group by document type
    grouped <- list()
    
    for (i in seq_along(sorted_citations)) {
      doc_type <- sorted_docs$tipo[i]
      if (!(doc_type %in% names(grouped))) {
        grouped[[doc_type]] <- character(0)
      }
      grouped[[doc_type]] <- c(grouped[[doc_type]], sorted_citations[i])
    }
    
    return(list(grouped = grouped, ungrouped = sorted_citations))
  } else {
    return(list(grouped = NULL, ungrouped = sorted_citations))
  }
}

#' Create citation guide for specific format
#' @param format Citation format
#' @return HTML content for guide
create_citation_guide <- function(format) {
  
  guides <- list(
    "ABNT" = div(
      p("A norma ABNT (Associação Brasileira de Normas Técnicas) é o padrão brasileiro para citações acadêmicas."),
      
      h6("Formato Básico:", class = "mt-3"),
      code("AUTOR. Título. Tipo nº número, data. Disponível em: <URL>. Acesso em: data."),
      
      h6("Exemplo:", class = "mt-3"),
      p(class = "font-monospace bg-light p-2",
        "BRASIL. Lei de Diretrizes e Bases da Educação Nacional. Lei nº 9.394, 20 de dezembro de 1996."
      ),
      
      h6("Observações:", class = "mt-3"),
      ul(
        li("Autor em MAIÚSCULAS"),
        li("Título em negrito ou itálico (opcional)"),
        li("Data por extenso"),
        li("URL entre < >")
      )
    ),
    
    "APA" = div(
      p("O estilo APA (American Psychological Association) é amplamente usado em ciências sociais."),
      
      h6("Formato Básico:", class = "mt-3"),
      code("Author. (Year). Title (Document type nº number). Retrieved from URL"),
      
      h6("Exemplo:", class = "mt-3"),
      p(class = "font-monospace bg-light p-2",
        "Brazil. (1996). Lei de Diretrizes e Bases da Educação Nacional (Lei nº 9.394)."
      ),
      
      h6("Observações:", class = "mt-3"),
      ul(
        li("Ano entre parênteses"),
        li("Título em itálico"),
        li("Primeira letra maiúscula"),
        li("Ponto final após cada elemento")
      )
    ),
    
    "Chicago" = div(
      p("O Chicago Manual of Style oferece dois sistemas: notas-bibliografia e autor-data."),
      
      h6("Formato Básico:", class = "mt-3"),
      code('Author. "Title." Document type nº number. Date. URL'),
      
      h6("Exemplo:", class = "mt-3"),
      p(class = "font-monospace bg-light p-2",
        'Brazil. "Lei de Diretrizes e Bases." Lei nº 9.394. December 20, 1996.'
      ),
      
      h6("Observações:", class = "mt-3"),
      ul(
        li("Título entre aspas"),
        li("Data completa em inglês"),
        li("URL sem formatação especial")
      )
    ),
    
    "MLA" = div(
      p("O estilo MLA (Modern Language Association) é comum em humanidades."),
      
      h6("Formato Básico:", class = "mt-3"),
      code('Author. "Title." Document type nº number, date. Web. Access date.'),
      
      h6("Exemplo:", class = "mt-3"),
      p(class = "font-monospace bg-light p-2",
        'Brazil. "Lei de Diretrizes e Bases." Lei nº 9.394, 20 Dec. 1996. Web. 15 Mar. 2024.'
      ),
      
      h6("Observações:", class = "mt-3"),
      ul(
        li("Título entre aspas"),
        li("Datas abreviadas"),
        li("Meio de publicação (Web)"),
        li("Data de acesso obrigatória")
      )
    ),
    
    "Vancouver" = div(
      p("O estilo Vancouver é usado principalmente em ciências médicas e biológicas."),
      
      h6("Formato Básico:", class = "mt-3"),
      code("Author. Title. Document type nº number. Year Month day. Available from: URL [cited date]."),
      
      h6("Exemplo:", class = "mt-3"),
      p(class = "font-monospace bg-light p-2",
        "Brazil. Lei de Diretrizes e Bases. Lei nº 9.394. 1996 Dec 20."
      ),
      
      h6("Observações:", class = "mt-3"),
      ul(
        li("Autor abreviado"),
        li("Data em formato ano-mês-dia"),
        li("Cited date entre colchetes")
      )
    ),
    
    "Harvard" = div(
      p("O sistema Harvard usa citações autor-data no texto e lista alfabética nas referências."),
      
      h6("Formato Básico:", class = "mt-3"),
      code("Author Year, Title, Document type nº number, viewed date, <URL>."),
      
      h6("Exemplo:", class = "mt-3"),
      p(class = "font-monospace bg-light p-2",
        "Brazil 1996, Lei de Diretrizes e Bases, Lei nº 9.394, viewed 15 March 2024, <http://...>."
      ),
      
      h6("Observações:", class = "mt-3"),
      ul(
        li("Ano após autor"),
        li("Título em itálico"),
        li("URL entre < >")
      )
    ),
    
    "NBR6023" = div(
      p("A NBR 6023:2018 é a norma ABNT atualizada para referências."),
      
      h6("Formato Básico:", class = "mt-3"),
      code("JURISDIÇÃO. Tipo nº número de data. Ementa. Dados da publicação. Disponível em: URL. Acesso em: data."),
      
      h6("Exemplo:", class = "mt-3"),
      p(class = "font-monospace bg-light p-2",
        "BRASIL. Lei nº 9.394 de 20 de dezembro de 1996. Estabelece as diretrizes e bases da educação nacional."
      ),
      
      h6("Observações:", class = "mt-3"),
      ul(
        li("Jurisdição em MAIÚSCULAS"),
        li("Incluir ementa quando disponível"),
        li("Elementos separados por ponto"),
        li("Acesso em: com data abreviada")
      )
    )
  )
  
  return(guides[[format]] %||% div(p("Guia não disponível para este formato.")))
}

#' Export citations in various formats
#' @param citations Generated citations
#' @param documents Original documents
#' @param format Export format
#' @param citation_style Citation style used
#' @param include_metadata Include additional metadata
#' @return Export content
export_citations <- function(citations, documents, format, citation_style, include_metadata = FALSE) {
  
  if (format == "txt") {
    # Plain text export
    content <- paste0(
      "Citações - ", citation_style, "\n",
      "Gerado em: ", format(Sys.time(), "%d/%m/%Y %H:%M"), "\n",
      paste0(rep("-", 50), collapse = ""), "\n\n"
    )
    
    # Individual citations
    content <- paste0(content, "CITAÇÕES INDIVIDUAIS:\n\n")
    for (i in seq_along(citations$individual)) {
      cit <- citations$individual[[i]]
      content <- paste0(content, i, ". ", cit$formatted, "\n\n")
    }
    
    # Reference list
    content <- paste0(content, "\nLISTA DE REFERÊNCIAS:\n\n")
    refs <- citations$reference_list
    if (!is.null(refs$grouped)) {
      for (type in names(refs$grouped)) {
        content <- paste0(content, "\n", type, ":\n")
        for (ref in refs$grouped[[type]]) {
          content <- paste0(content, ref, "\n")
        }
      }
    } else {
      for (ref in refs$ungrouped) {
        content <- paste0(content, ref, "\n")
      }
    }
    
    return(content)
    
  } else if (format == "bibtex") {
    # BibTeX export
    content <- ""
    
    for (i in seq_along(documents)) {
      doc <- documents[i, ]
      
      # Generate BibTeX key
      key <- paste0(
        str_extract(doc$tipo, "^\\w+"),
        doc$numero,
        format(as.Date(doc$data), "%Y")
      )
      
      # BibTeX entry
      entry <- paste0(
        "@legislation{", key, ",\n",
        "  title = {", doc$titulo, "},\n",
        "  author = {", determine_institution_bibtex(doc$estado), "},\n",
        "  year = {", format(as.Date(doc$data), "%Y"), "},\n",
        "  type = {", doc$tipo, "},\n",
        "  number = {", doc$numero, "},\n",
        "  date = {", doc$data, "}"
      )
      
      if (!is.null(doc$url) && !is.na(doc$url)) {
        entry <- paste0(entry, ",\n  url = {", doc$url, "}")
      }
      
      entry <- paste0(entry, "\n}\n\n")
      content <- paste0(content, entry)
    }
    
    return(content)
    
  } else if (format == "ris") {
    # RIS export
    content <- ""
    
    for (i in seq_along(documents)) {
      doc <- documents[i, ]
      
      entry <- paste0(
        "TY  - STAT\n",
        "TI  - ", doc$titulo, "\n",
        "AU  - ", determine_institution_ris(doc$estado), "\n",
        "PY  - ", format(as.Date(doc$data), "%Y"), "\n",
        "DA  - ", format(as.Date(doc$data), "%Y/%m/%d"), "\n",
        "M1  - ", doc$tipo, " ", doc$numero, "\n"
      )
      
      if (!is.null(doc$url) && !is.na(doc$url)) {
        entry <- paste0(entry, "UR  - ", doc$url, "\n")
      }
      
      entry <- paste0(entry, "ER  - \n\n")
      content <- paste0(content, entry)
    }
    
    return(content)
    
  } else if (format == "json") {
    # JSON export
    export_data <- list(
      metadata = list(
        generated_at = Sys.time(),
        citation_style = citation_style,
        total_documents = nrow(documents)
      ),
      citations = citations$individual,
      reference_list = citations$reference_list,
      documents = if (include_metadata) documents else NULL
    )
    
    return(export_data)
  }
  
  return("")
}

#' Helper functions for export formats
determine_institution_bibtex <- function(state) {
  if (!is.null(state) && !is.na(state)) {
    return(paste0("{", get_state_name(state), ", Brazil}"))
  }
  return("{Brazil}")
}

determine_institution_ris <- function(state) {
  if (!is.null(state) && !is.na(state)) {
    return(paste0(get_state_name(state), ", Brazil"))
  }
  return("Brazil")
}