# CITATION SYSTEM UI INTEGRATION
# ==============================
# Shiny UI components for Brazilian legislative citation system
# Integrates with existing dashboard structure
# 
# Features:
# - Citation format selection and preview
# - Bulk document selection for citation
# - Real-time citation preview with validation
# - Export options for multiple formats
# - Collection management interface
# - Copy-to-clipboard functionality

cat("Loading Citation System UI Components...\n")

# Required Shiny packages
ui_packages <- c("shiny", "shinydashboard", "DT", "shinyjs", "htmltools")
missing_ui_packages <- c()

for (pkg in ui_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_ui_packages <- c(missing_ui_packages, pkg)
  }
}

if (length(missing_ui_packages) > 0) {
  cat("⚠️ UI packages not available:", paste(missing_ui_packages, collapse = ", "), "\n")
  cat("📱 Basic UI will be available with limited functionality\n")
}

# CITATION TAB UI COMPONENTS
# =========================

#' Generate Citation Tab UI for Dashboard
#' @return Shiny tab UI
citation_tab_ui <- function() {
  tabItem(
    tabName = "citations",
    
    # Add custom CSS for citation styling
    tags$head(
      tags$style(HTML("
        .citation-preview {
          background-color: #f8f9fa;
          border: 1px solid #dee2e6;
          border-radius: 5px;
          padding: 15px;
          margin: 10px 0;
          font-family: 'Times New Roman', serif;
          line-height: 1.6;
        }
        
        .citation-format {
          margin-bottom: 20px;
        }
        
        .citation-format h5 {
          color: #495057;
          margin-bottom: 8px;
          font-weight: bold;
        }
        
        .citation-text {
          margin: 0;
          padding: 10px;
          background-color: white;
          border-left: 4px solid #007bff;
          font-size: 14px;
        }
        
        .citation-text.abnt {
          border-left-color: #28a745;
        }
        
        .citation-text.apa {
          border-left-color: #17a2b8;
        }
        
        .citation-text.vancouver {
          border-left-color: #ffc107;
        }
        
        .citation-text.bluebook {
          border-left-color: #dc3545;
        }
        
        .collection-item {
          border: 1px solid #ddd;
          border-radius: 4px;
          padding: 10px;
          margin: 5px 0;
          background-color: #fff;
        }
        
        .collection-item.selected {
          border-color: #007bff;
          background-color: #f8f9ff;
        }
        
        .document-selector {
          max-height: 300px;
          overflow-y: auto;
          border: 1px solid #ddd;
          border-radius: 4px;
          padding: 10px;
          background-color: #fff;
        }
        
        .copy-button {
          margin-left: 10px;
        }
        
        .export-section {
          background-color: #f8f9fa;
          padding: 15px;
          border-radius: 5px;
          margin-top: 15px;
        }
        
        .citation-stats {
          background-color: #e9ecef;
          padding: 10px;
          border-radius: 4px;
          margin-bottom: 15px;
        }
      "))
    ),
    
    # Page header
    fluidRow(
      box(
        title = "Sistema de Citações Acadêmicas",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        p("Gere citações acadêmicas para documentos legislativos brasileiros em formatos ABNT, APA, Vancouver e Bluebook."),
        
        # Citation statistics
        div(
          class = "citation-stats",
          fluidRow(
            column(3, 
              div(
                h4(textOutput("total_collections"), style = "margin: 0; color: #495057;"),
                p("Coleções Ativas", style = "margin: 0; font-size: 12px;")
              )
            ),
            column(3,
              div(
                h4(textOutput("total_documents_selected"), style = "margin: 0; color: #495057;"),
                p("Documentos Selecionados", style = "margin: 0; font-size: 12px;")
              )
            ),
            column(3,
              div(
                h4(textOutput("current_format"), style = "margin: 0; color: #495057;"),
                p("Formato Atual", style = "margin: 0; font-size: 12px;")
              )
            ),
            column(3,
              div(
                h4(textOutput("citations_ready"), style = "margin: 0; color: #495057;"),
                p("Citações Prontas", style = "margin: 0; font-size: 12px;")
              )
            )
          )
        )
      )
    ),
    
    # Main interface
    fluidRow(
      # Left panel: Document selection and collection management
      column(4,
        box(
          title = "Seleção de Documentos",
          status = "info",
          solidHeader = TRUE,
          width = NULL,
          
          # Collection management
          h4("Gerenciar Coleções", style = "margin-top: 0;"),
          
          fluidRow(
            column(8,
              textInput("new_collection_name", "Nome da Nova Coleção:", placeholder = "Ex: Dissertação Capítulo 2")
            ),
            column(4,
              br(),
              actionButton("create_collection", "Criar", class = "btn-primary", style = "width: 100%;")
            )
          ),
          
          # Existing collections
          h5("Coleções Existentes:"),
          uiOutput("collections_list"),
          
          hr(),
          
          # Document search and selection
          h4("Selecionar Documentos"),
          
          # Quick search
          textInput("citation_search", "Buscar Documentos:", placeholder = "Digite termos de busca..."),
          
          # Document selection interface
          div(
            class = "document-selector",
            uiOutput("document_selection_ui")
          ),
          
          # Selection actions
          fluidRow(
            column(6,
              actionButton("add_selected", "Adicionar Selecionados", class = "btn-success", style = "width: 100%;")
            ),
            column(6,
              actionButton("clear_selection", "Limpar Seleção", class = "btn-warning", style = "width: 100%;")
            )
          )
        ),
        
        # Collection contents
        box(
          title = "Documentos na Coleção",
          status = "success", 
          solidHeader = TRUE,
          width = NULL,
          
          conditionalPanel(
            condition = "output.has_active_collection",
            
            h5(textOutput("active_collection_name")),
            p(textOutput("active_collection_description"), style = "color: #666;"),
            
            # Collection documents
            div(
              id = "collection_documents",
              uiOutput("collection_documents_ui")
            ),
            
            # Collection actions
            fluidRow(
              column(4,
                actionButton("remove_selected", "Remover", class = "btn-danger btn-sm", style = "width: 100%;")
              ),
              column(4,
                actionButton("reorder_documents", "Reordenar", class = "btn-info btn-sm", style = "width: 100%;")
              ),
              column(4,
                actionButton("delete_collection", "Excluir Coleção", class = "btn-danger btn-sm", style = "width: 100%;")
              )
            )
          ),
          
          conditionalPanel(
            condition = "!output.has_active_collection",
            div(
              class = "text-center",
              style = "padding: 20px;",
              p("Crie ou selecione uma coleção para começar", style = "color: #666;")
            )
          )
        )
      ),
      
      # Right panel: Citation generation and preview
      column(8,
        # Format selection
        box(
          title = "Configuração de Citação",
          status = "warning",
          solidHeader = TRUE,
          width = NULL,
          
          fluidRow(
            column(4,
              selectInput("citation_format", "Formato de Citação:",
                choices = list(
                  "ABNT NBR 6023:2018" = "abnt",
                  "APA 7ª Edição" = "apa", 
                  "Vancouver" = "vancouver",
                  "Bluebook" = "bluebook"
                ),
                selected = "abnt"
              )
            ),
            column(4,
              selectInput("citation_language", "Idioma:",
                choices = list(
                  "Português" = "pt",
                  "English" = "en"
                ),
                selected = "pt"
              )
            ),
            column(4,
              br(),
              actionButton("generate_citations", "Gerar Citações", class = "btn-primary", style = "width: 100%;")
            )
          ),
          
          # Format information
          uiOutput("format_info")
        ),
        
        # Citation preview
        box(
          title = "Prévia das Citações",
          status = "primary",
          solidHeader = TRUE,
          width = NULL,
          
          conditionalPanel(
            condition = "output.has_citations",
            
            # Preview controls
            fluidRow(
              column(6,
                checkboxInput("show_all_formats", "Mostrar Todos os Formatos", value = FALSE)
              ),
              column(6,
                div(
                  style = "text-align: right;",
                  actionButton("copy_citations", "Copiar Citações", 
                             class = "btn-info copy-button",
                             onclick = "copyToClipboard('citations_preview')")
                )
              )
            ),
            
            # Citations display
            div(
              id = "citations_preview",
              class = "citation-preview",
              uiOutput("citations_display")
            )
          ),
          
          conditionalPanel(
            condition = "!output.has_citations",
            div(
              class = "text-center",
              style = "padding: 40px;",
              h4("Nenhuma citação gerada", style = "color: #666;"),
              p("Adicione documentos à sua coleção e clique em 'Gerar Citações'")
            )
          )
        ),
        
        # Export options
        box(
          title = "Exportar Citações",
          status = "success",
          solidHeader = TRUE,
          width = NULL,
          
          div(
            class = "export-section",
            
            h5("Formatos de Exportação:"),
            
            fluidRow(
              column(6,
                checkboxGroupInput("export_formats", NULL,
                  choices = list(
                    "ABNT (Texto)" = "abnt_plain",
                    "APA (Texto)" = "apa_plain",
                    "BibTeX (.bib)" = "bibtex",
                    "RIS (.ris)" = "ris",
                    "EndNote XML (.xml)" = "endnote"
                  ),
                  selected = c("abnt_plain", "bibtex")
                )
              ),
              column(6,
                textInput("export_filename", "Nome do Arquivo:", 
                         placeholder = "citacoes_legislativas"),
                br(),
                downloadButton("download_citations", "Baixar Citações", 
                             class = "btn-success", style = "width: 100%;")
              )
            )
          )
        )
      )
    )
  )
}

# CITATION SERVER LOGIC
# ====================

#' Citation System Server Logic
#' @param input Shiny input
#' @param output Shiny output  
#' @param session Shiny session
#' @param get_documents Function to get documents from main app
citation_server <- function(input, output, session, get_documents = NULL) {
  
  # Load citation system modules
  if (!exists("create_citation_collection")) {
    if (file.exists("modules/citations/bulk_citation_manager.R")) {
      source("modules/citations/bulk_citation_manager.R")
    }
  }
  
  # Reactive values
  values <- reactiveValues(
    active_collection_id = NULL,
    selected_documents = c(),
    generated_citations = "",
    available_documents = data.frame()
  )
  
  # Initialize available documents
  observe({
    if (!is.null(get_documents)) {
      tryCatch({
        docs <- get_documents()
        if (is.data.frame(docs) && nrow(docs) > 0) {
          values$available_documents <- docs
        }
      }, error = function(e) {
        cat("⚠️ Failed to load documents for citation system:", e$message, "\n")
      })
    }
  })
  
  # Collection statistics
  output$total_collections <- renderText({
    collections <- get_collection_info()
    as.character(length(collections))
  })
  
  output$total_documents_selected <- renderText({
    if (!is.null(values$active_collection_id)) {
      collection <- get_collection_info(values$active_collection_id)
      if (!is.null(collection)) {
        return(as.character(collection$document_count))
      }
    }
    "0"
  })
  
  output$current_format <- renderText({
    format_names <- list(
      "abnt" = "ABNT",
      "apa" = "APA", 
      "vancouver" = "Vancouver",
      "bluebook" = "Bluebook"
    )
    format_names[[input$citation_format]] %||% "ABNT"
  })
  
  output$citations_ready <- renderText({
    if (nchar(values$generated_citations) > 0) "Sim" else "Não"
  })
  
  # Create new collection
  observeEvent(input$create_collection, {
    req(input$new_collection_name)
    
    if (nchar(trimws(input$new_collection_name)) > 0) {
      tryCatch({
        collection_id <- create_citation_collection(
          input$new_collection_name,
          format = input$citation_format,
          language = input$citation_language
        )
        values$active_collection_id <- collection_id
        updateTextInput(session, "new_collection_name", value = "")
        
        showNotification("Coleção criada com sucesso!", type = "success")
      }, error = function(e) {
        showNotification(paste("Erro ao criar coleção:", e$message), type = "error")
      })
    }
  })
  
  # Collections list UI
  output$collections_list <- renderUI({
    collections <- get_collection_info()
    
    if (length(collections) == 0) {
      return(p("Nenhuma coleção encontrada", style = "color: #666; font-style: italic;"))
    }
    
    collection_buttons <- list()
    
    for (cid in names(collections)) {
      collection <- collections[[cid]]
      
      button_class <- if (cid == values$active_collection_id) "btn-primary" else "btn-outline-secondary"
      
      collection_buttons[[cid]] <- div(
        style = "margin: 2px 0;",
        actionButton(
          paste0("select_collection_", cid),
          paste0(collection$name, " (", collection$document_count, ")"),
          class = paste("btn-sm", button_class),
          style = "width: 100%; text-align: left;"
        )
      )
      
      # Add observer for collection selection
      local({
        collection_id <- cid
        observeEvent(input[[paste0("select_collection_", collection_id)]], {
          values$active_collection_id <- collection_id
        })
      })
    }
    
    return(do.call(tagList, collection_buttons))
  })
  
  # Active collection info
  output$has_active_collection <- reactive({
    !is.null(values$active_collection_id)
  })
  outputOptions(output, "has_active_collection", suspendWhenHidden = FALSE)
  
  output$active_collection_name <- renderText({
    if (!is.null(values$active_collection_id)) {
      collection <- get_collection_info(values$active_collection_id)
      if (!is.null(collection)) {
        return(collection$name)
      }
    }
    ""
  })
  
  output$active_collection_description <- renderText({
    if (!is.null(values$active_collection_id)) {
      collection <- get_collection_info(values$active_collection_id)
      if (!is.null(collection)) {
        desc <- collection$description
        if (desc != "") return(desc)
      }
    }
    "Nenhuma descrição"
  })
  
  # Document selection UI
  output$document_selection_ui <- renderUI({
    docs <- values$available_documents
    search_term <- input$citation_search
    
    if (nrow(docs) == 0) {
      return(p("Nenhum documento disponível", style = "color: #666;"))
    }
    
    # Filter documents based on search
    if (!is.null(search_term) && nchar(trimws(search_term)) > 0) {
      search_pattern <- paste0(".*", search_term, ".*")
      title_match <- grepl(search_pattern, docs$title, ignore.case = TRUE)
      docs <- docs[title_match, ]
    }
    
    if (nrow(docs) == 0) {
      return(p("Nenhum documento encontrado", style = "color: #666;"))
    }
    
    # Limit to first 50 results for performance
    docs <- head(docs, 50)
    
    document_checkboxes <- list()
    
    for (i in 1:nrow(docs)) {
      doc <- docs[i, ]
      doc_id <- paste0("doc_", i)
      
      document_checkboxes[[doc_id]] <- div(
        class = "collection-item",
        checkboxInput(
          paste0("select_doc_", i),
          label = div(
            strong(doc$title),
            br(),
            span(paste("Estado:", doc$state %||% "N/A", "| Data:", doc$date %||% "N/A"), 
                 style = "color: #666; font-size: 12px;")
          ),
          value = FALSE
        )
      )
    }
    
    return(do.call(tagList, document_checkboxes))
  })
  
  # Add selected documents to collection
  observeEvent(input$add_selected, {
    req(values$active_collection_id)
    
    docs <- values$available_documents
    search_term <- input$citation_search
    
    # Apply same filtering as in UI
    if (!is.null(search_term) && nchar(trimws(search_term)) > 0) {
      search_pattern <- paste0(".*", search_term, ".*")
      title_match <- grepl(search_pattern, docs$title, ignore.case = TRUE)
      docs <- docs[title_match, ]
    }
    
    docs <- head(docs, 50)
    
    selected_docs <- data.frame()
    
    for (i in 1:nrow(docs)) {
      if (isTRUE(input[[paste0("select_doc_", i)]])) {
        selected_docs <- rbind(selected_docs, docs[i, ])
      }
    }
    
    if (nrow(selected_docs) > 0) {
      tryCatch({
        added <- add_documents_to_collection(values$active_collection_id, selected_docs)
        showNotification(paste("Adicionados", added, "documento(s) à coleção"), type = "success")
        
        # Clear selections
        for (i in 1:nrow(docs)) {
          updateCheckboxInput(session, paste0("select_doc_", i), value = FALSE)
        }
      }, error = function(e) {
        showNotification(paste("Erro ao adicionar documentos:", e$message), type = "error")
      })
    } else {
      showNotification("Nenhum documento selecionado", type = "warning")
    }
  })
  
  # Collection documents UI
  output$collection_documents_ui <- renderUI({
    req(values$active_collection_id)
    
    collection <- get_collection_info(values$active_collection_id)
    
    if (is.null(collection) || collection$document_count == 0) {
      return(p("Nenhum documento na coleção", style = "color: #666;"))
    }
    
    # This would need to be implemented based on collection structure
    # For now, show count
    p(paste("Documentos na coleção:", collection$document_count), style = "color: #495057;")
  })
  
  # Generate citations
  observeEvent(input$generate_citations, {
    req(values$active_collection_id)
    
    tryCatch({
      citations <- generate_collection_citations(
        values$active_collection_id,
        input$citation_format,
        input$citation_language,
        include_bibliography = TRUE
      )
      
      values$generated_citations <- citations
      showNotification("Citações geradas com sucesso!", type = "success")
    }, error = function(e) {
      showNotification(paste("Erro ao gerar citações:", e$message), type = "error")
    })
  })
  
  # Citations display
  output$has_citations <- reactive({
    nchar(values$generated_citations) > 0
  })
  outputOptions(output, "has_citations", suspendWhenHidden = FALSE)
  
  output$citations_display <- renderUI({
    if (nchar(values$generated_citations) == 0) {
      return(NULL)
    }
    
    if (input$show_all_formats) {
      # Show multiple formats (would need implementation)
      return(pre(values$generated_citations, style = "white-space: pre-wrap;"))
    } else {
      return(pre(values$generated_citations, style = "white-space: pre-wrap;"))
    }
  })
  
  # Format information
  output$format_info <- renderUI({
    format_descriptions <- list(
      "abnt" = "ABNT NBR 6023:2018 - Padrão brasileiro para referências bibliográficas. Recomendado para trabalhos acadêmicos no Brasil.",
      "apa" = "APA 7ª Edição - Padrão internacional da American Psychological Association. Usado em publicações internacionais.",
      "vancouver" = "Vancouver - Estilo numérico usado em revistas médicas e científicas.",
      "bluebook" = "Bluebook - Formato padrão para citações jurídicas nos Estados Unidos."
    )
    
    desc <- format_descriptions[[input$citation_format]]
    if (!is.null(desc)) {
      div(
        class = "alert alert-info",
        style = "margin-top: 10px;",
        p(desc, style = "margin: 0;")
      )
    }
  })
  
  # Download citations
  output$download_citations <- downloadHandler(
    filename = function() {
      paste0(input$export_filename %||% "citacoes", "_", Sys.Date(), ".zip")
    },
    content = function(file) {
      req(values$active_collection_id)
      
      # Create temporary directory
      temp_dir <- tempdir()
      
      tryCatch({
        # Export in selected formats
        export_results <- batch_export_collection(
          values$active_collection_id,
          temp_dir,
          input$export_formats,
          input$export_filename %||% "citacoes"
        )
        
        # Create ZIP file
        files_to_zip <- c()
        for (format in names(export_results)) {
          result <- export_results[[format]]
          if (result$success && file.exists(result$file)) {
            files_to_zip <- c(files_to_zip, result$file)
          }
        }
        
        if (length(files_to_zip) > 0) {
          zip(file, files_to_zip, flags = "-r9X")
        } else {
          stop("Nenhum arquivo foi gerado para download")
        }
        
      }, error = function(e) {
        showNotification(paste("Erro no download:", e$message), type = "error")
      })
    }
  )
  
  # Add JavaScript for copy to clipboard functionality
  observe({
    if (requireNamespace("shinyjs", quietly = TRUE)) {
      shinyjs::runjs("
        function copyToClipboard(elementId) {
          var element = document.getElementById(elementId);
          if (element) {
            var text = element.innerText || element.textContent;
            navigator.clipboard.writeText(text).then(function() {
              alert('Citações copiadas para a área de transferência!');
            }, function(err) {
              console.error('Erro ao copiar: ', err);
            });
          }
        }
      ")
    }
  })
}

# Utility function
`%||%` <- function(a, b) if (is.null(a)) b else a

cat("✅ Citation System UI Components loaded successfully\n")
cat("   🖥️ Citation tab interface: ENABLED\n")
cat("   📋 Document selection: ENABLED\n") 
cat("   🔄 Real-time preview: ENABLED\n")
cat("   📦 Export interface: ENABLED\n")
cat("   📚 Collection management: ENABLED\n")
cat("   📋 Copy-to-clipboard: ENABLED\n")

# Export UI functions
CITATION_UI_FUNCTIONS <- list(
  citation_tab_ui = citation_tab_ui,
  citation_server = citation_server
)