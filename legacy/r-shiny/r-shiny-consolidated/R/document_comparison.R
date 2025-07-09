# Document Comparison and Diff Visualization for Monitor Legislativo v4
# Side-by-side comparison with highlighted differences and academic analysis

library(shiny)
library(htmltools)
library(dplyr)
library(stringr)
library(diffr)
library(DT)
library(shinycssloaders)
library(htmlwidgets)

# Document comparison configuration
COMPARISON_CONFIG <- list(
  max_documents_compare = 4,
  diff_context_lines = 3,
  similarity_threshold = 0.7,
  highlight_colors = list(
    added = "#d4edda",
    removed = "#f8d7da", 
    modified = "#fff3cd",
    unchanged = "#ffffff"
  ),
  comparison_modes = list(
    "text" = "Comparação Textual",
    "structure" = "Comparação Estrutural",
    "semantic" = "Comparação Semântica",
    "metadata" = "Comparação de Metadados"
  )
)

#' Create document comparison interface
#' @param id Module ID
#' @return Document comparison UI
document_comparison_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "document-comparison-container",
    
    # Comparison header with controls
    div(
      class = "comparison-header",
      style = "background: #f8f9fa; padding: 15px; border-radius: 8px 8px 0 0; border-bottom: 1px solid #dee2e6;",
      
      fluidRow(
        column(8,
          h4("📊 Comparação de Documentos", style = "margin: 0; color: #2c3e50;")
        ),
        
        column(4,
          div(
            class = "comparison-controls text-end",
            
            # Comparison mode selector
            selectInput(
              ns("comparison_mode"),
              NULL,
              choices = COMPARISON_CONFIG$comparison_modes,
              selected = "text",
              width = "200px"
            ),
            
            # Export comparison button
            actionButton(
              ns("export_comparison"),
              "📄 Exportar Comparação",
              class = "btn btn-outline-primary btn-sm"
            )
          )
        )
      )
    ),
    
    # Document selection panel
    div(
      class = "document-selection-panel",
      style = "background: #ffffff; padding: 15px; border-bottom: 1px solid #dee2e6;",
      
      h6("Selecionar Documentos para Comparação"),
      
      fluidRow(
        column(6,
          div(
            class = "document-selector",
            h6("📄 Documento Principal", class = "text-primary"),
            uiOutput(ns("primary_document_selector")),
            
            conditionalPanel(
              condition = paste0("output['", ns("has_primary_document"), "']"),
              div(
                class = "document-preview mt-2 p-2 border rounded",
                style = "background: #f8f9fa; max-height: 100px; overflow-y: auto;",
                htmlOutput(ns("primary_document_preview"))
              )
            )
          )
        ),
        
        column(6,
          div(
            class = "documents-to-compare",
            h6("📑 Documentos para Comparar", class = "text-info"),
            uiOutput(ns("comparison_documents_selector")),
            
            div(
              class = "selected-documents mt-2",
              uiOutput(ns("selected_documents_list"))
            )
          )
        )
      ),
      
      div(
        class = "text-center mt-3",
        actionButton(
          ns("start_comparison"),
          "🔍 Iniciar Comparação",
          class = "btn btn-success btn-lg",
          disabled = TRUE
        ),
        
        actionButton(
          ns("clear_selection"),
          "🗑️ Limpar Seleção",
          class = "btn btn-outline-secondary btn-sm ms-2"
        )
      )
    ),
    
    # Comparison results area
    div(
      class = "comparison-results-area",
      style = "background: white; min-height: 400px;",
      
      # Loading indicator
      conditionalPanel(
        condition = paste0("input['", ns("start_comparison"), "'] > 0 && !output['", ns("comparison_ready"), "']"),
        div(
          class = "text-center py-5",
          withSpinner(
            div(
              h4("Processando comparação...", class = "text-muted"),
              p("Analisando diferenças entre documentos", class = "text-muted")
            ),
            type = 4,
            color = "#0d6efd"
          )
        )
      ),
      
      # Comparison results
      conditionalPanel(
        condition = paste0("output['", ns("comparison_ready"), "']"),
        
        # Comparison summary
        div(
          class = "comparison-summary p-3 mb-3",
          style = "background: #e3f2fd; border-radius: 8px;",
          uiOutput(ns("comparison_summary"))
        ),
        
        # Comparison visualization tabs
        navset_card_tab(
          id = ns("comparison_tabs"),
          
          nav_panel(
            "📄 Visualização Lado a Lado",
            div(
              class = "side-by-side-comparison",
              style = "height: 600px; overflow-y: auto;",
              uiOutput(ns("side_by_side_view"))
            )
          ),
          
          nav_panel(
            "🔍 Diferenças Destacadas", 
            div(
              class = "diff-highlighted-view",
              style = "height: 600px; overflow-y: auto;",
              uiOutput(ns("diff_highlighted_view"))
            )
          ),
          
          nav_panel(
            "📊 Análise Estatística",
            div(
              class = "statistical-analysis",
              uiOutput(ns("statistical_analysis"))
            )
          ),
          
          nav_panel(
            "🏗️ Comparação Estrutural",
            div(
              class = "structural-comparison",
              uiOutput(ns("structural_comparison"))
            )
          )
        )
      ),
      
      # No comparison state
      conditionalPanel(
        condition = paste0("input['", ns("start_comparison"), "'] == 0"),
        div(
          class = "no-comparison-state text-center py-5",
          icon("balance-scale", class = "fa-3x text-muted mb-3"),
          h4("Comparação de Documentos", class = "text-muted"),
          p("Selecione documentos acima para comparar diferenças, semelhanças e padrões legislativos", class = "text-muted")
        )
      )
    )
  )
}

#' Document comparison server function
#' @param id Module ID
#' @param available_documents Reactive containing available documents
document_comparison_server <- function(id, available_documents) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for comparison state
    values <- reactiveValues(
      primary_document = NULL,
      comparison_documents = list(),
      comparison_results = NULL,
      processing = FALSE
    )
    
    # ========================================================================
    # DOCUMENT SELECTION
    # ========================================================================
    
    output$primary_document_selector <- renderUI({
      if (is.null(available_documents()) || nrow(available_documents()) == 0) {
        return(p("Nenhum documento disponível", class = "text-muted"))
      }
      
      docs <- available_documents()
      choices <- setNames(1:nrow(docs), paste0(docs$titulo, " (", docs$tipo, ")"))
      
      selectInput(
        session$ns("primary_doc_id"),
        "Documento principal:",
        choices = c("Selecionar..." = "", choices),
        selected = ""
      )
    })
    
    output$comparison_documents_selector <- renderUI({
      if (is.null(available_documents()) || nrow(available_documents()) == 0) {
        return(p("Nenhum documento disponível", class = "text-muted"))
      }
      
      docs <- available_documents()
      
      # Exclude primary document from choices
      exclude_primary <- if (!is.null(input$primary_doc_id) && input$primary_doc_id != "") {
        as.numeric(input$primary_doc_id)
      } else {
        NULL
      }
      
      available_for_comparison <- if (!is.null(exclude_primary)) {
        docs[-exclude_primary, ]
      } else {
        docs
      }
      
      if (nrow(available_for_comparison) == 0) {
        return(p("Selecione um documento principal primeiro", class = "text-muted"))
      }
      
      choices <- setNames(
        which(1:nrow(docs) %in% rownames(available_for_comparison)),
        paste0(available_for_comparison$titulo, " (", available_for_comparison$tipo, ")")
      )
      
      checkboxGroupInput(
        session$ns("comparison_doc_ids"),
        "Documentos para comparar:",
        choices = choices,
        selected = NULL
      )
    })
    
    # Update primary document when selected
    observeEvent(input$primary_doc_id, {
      if (!is.null(input$primary_doc_id) && input$primary_doc_id != "" && !is.null(available_documents())) {
        doc_index <- as.numeric(input$primary_doc_id)
        values$primary_document <- available_documents()[doc_index, ]
        
        # Enable comparison button if we have comparison documents
        session$sendCustomMessage("updateComparisonButton", 
          length(input$comparison_doc_ids) > 0
        )
      } else {
        values$primary_document <- NULL
      }
    })
    
    # Update comparison documents when selected
    observeEvent(input$comparison_doc_ids, {
      if (!is.null(input$comparison_doc_ids) && length(input$comparison_doc_ids) > 0 && !is.null(available_documents())) {
        doc_indices <- as.numeric(input$comparison_doc_ids)
        values$comparison_documents <- available_documents()[doc_indices, ]
        
        # Enable comparison button if we have primary document
        updateActionButton(
          session, "start_comparison",
          disabled = is.null(values$primary_document)
        )
      } else {
        values$comparison_documents <- list()
        updateActionButton(session, "start_comparison", disabled = TRUE)
      }
    })
    
    # ========================================================================
    # DOCUMENT PREVIEWS
    # ========================================================================
    
    output$has_primary_document <- reactive({
      !is.null(values$primary_document)
    })
    outputOptions(output, "has_primary_document", suspendWhenHidden = FALSE)
    
    output$primary_document_preview <- renderUI({
      if (is.null(values$primary_document)) return(NULL)
      
      doc <- values$primary_document
      div(
        strong(doc$titulo),
        br(),
        span(paste("Tipo:", doc$tipo), class = "text-muted"),
        br(),
        span(paste("Data:", format(as.Date(doc$data), "%d/%m/%Y")), class = "text-muted")
      )
    })
    
    output$selected_documents_list <- renderUI({
      if (is.null(values$comparison_documents) || nrow(values$comparison_documents) == 0) {
        return(p("Nenhum documento selecionado", class = "text-muted"))
      }
      
      div(
        class = "selected-docs-list",
        lapply(1:nrow(values$comparison_documents), function(i) {
          doc <- values$comparison_documents[i, ]
          div(
            class = "selected-doc-item p-2 mb-1 border rounded",
            style = "background: #f8f9fa;",
            div(
              class = "d-flex justify-content-between align-items-center",
              div(
                strong(str_trunc(doc$titulo, 40)),
                br(),
                span(paste(doc$tipo, "-", format(as.Date(doc$data), "%d/%m/%Y")), 
                     class = "text-muted small")
              ),
              span(paste("Doc", i), class = "badge bg-info")
            )
          )
        })
      )
    })
    
    # ========================================================================
    # COMPARISON PROCESSING
    # ========================================================================
    
    observeEvent(input$start_comparison, {
      if (is.null(values$primary_document) || is.null(values$comparison_documents) || 
          nrow(values$comparison_documents) == 0) {
        showNotification("Selecione documentos para comparar", type = "warning")
        return()
      }
      
      values$processing <- TRUE
      
      showNotification("Iniciando comparação de documentos...", type = "message")
      
      # Perform comparison analysis
      comparison_results <- perform_document_comparison(
        primary_doc = values$primary_document,
        comparison_docs = values$comparison_documents,
        mode = input$comparison_mode
      )
      
      values$comparison_results <- comparison_results
      values$processing <- FALSE
      
      showNotification("Comparação concluída!", type = "success")
    })
    
    # Clear selection
    observeEvent(input$clear_selection, {
      updateSelectInput(session, "primary_doc_id", selected = "")
      updateCheckboxGroupInput(session, "comparison_doc_ids", selected = character(0))
      values$primary_document <- NULL
      values$comparison_documents <- list()
      values$comparison_results <- NULL
    })
    
    # ========================================================================
    # COMPARISON RESULTS OUTPUTS
    # ========================================================================
    
    output$comparison_ready <- reactive({
      !is.null(values$comparison_results) && !values$processing
    })
    outputOptions(output, "comparison_ready", suspendWhenHidden = FALSE)
    
    output$comparison_summary <- renderUI({
      if (is.null(values$comparison_results)) return(NULL)
      
      results <- values$comparison_results
      
      div(
        class = "comparison-summary-content",
        
        fluidRow(
          column(3,
            div(
              class = "summary-metric text-center",
              h3(length(results$documents), class = "text-primary mb-1"),
              small("Documentos Comparados", class = "text-muted")
            )
          ),
          
          column(3,
            div(
              class = "summary-metric text-center",
              h3(paste0(round(results$similarity_score * 100), "%"), class = "text-success mb-1"),
              small("Similaridade Média", class = "text-muted")
            )
          ),
          
          column(3,
            div(
              class = "summary-metric text-center",
              h3(results$total_differences, class = "text-warning mb-1"),
              small("Diferenças Encontradas", class = "text-muted")
            )
          ),
          
          column(3,
            div(
              class = "summary-metric text-center",
              h3(results$common_elements, class = "text-info mb-1"),
              small("Elementos Comuns", class = "text-muted")
            )
          )
        ),
        
        hr(),
        
        div(
          class = "comparison-insights",
          h6("💡 Principais Insights:", class = "mb-2"),
          
          if (length(results$insights) > 0) {
            div(
              class = "insights-list",
              lapply(results$insights, function(insight) {
                p(paste("•", insight), class = "mb-1 text-dark")
              })
            )
          } else {
            p("Nenhum insight específico identificado", class = "text-muted")
          }
        )
      )
    })
    
    output$side_by_side_view <- renderUI({
      if (is.null(values$comparison_results)) return(NULL)
      
      create_side_by_side_comparison(values$comparison_results)
    })
    
    output$diff_highlighted_view <- renderUI({
      if (is.null(values$comparison_results)) return(NULL)
      
      create_diff_highlighted_view(values$comparison_results)
    })
    
    output$statistical_analysis <- renderUI({
      if (is.null(values$comparison_results)) return(NULL)
      
      create_statistical_analysis(values$comparison_results)
    })
    
    output$structural_comparison <- renderUI({
      if (is.null(values$comparison_results)) return(NULL)
      
      create_structural_comparison(values$comparison_results)
    })
    
    # ========================================================================
    # EXPORT FUNCTIONALITY
    # ========================================================================
    
    observeEvent(input$export_comparison, {
      if (is.null(values$comparison_results)) {
        showNotification("Nenhuma comparação para exportar", type = "warning")
        return()
      }
      
      # Generate comparison report
      export_file <- generate_comparison_report(
        values$comparison_results,
        format = "html"
      )
      
      if (!is.null(export_file)) {
        session$sendCustomMessage("downloadFile", list(
          filename = paste0("comparacao_documentos_", Sys.Date(), ".html"),
          filepath = export_file
        ))
        
        showNotification("Relatório de comparação gerado!", type = "success")
      } else {
        showNotification("Erro ao gerar relatório", type = "error")
      }
    })
  })
}

#' Perform comprehensive document comparison
#' @param primary_doc Primary document
#' @param comparison_docs Documents to compare against primary
#' @param mode Comparison mode
#' @return Comparison results list
perform_document_comparison <- function(primary_doc, comparison_docs, mode = "text") {
  
  log_event("Performing document comparison")
  
  # Initialize results structure
  results <- list(
    primary_document = primary_doc,
    comparison_documents = comparison_docs,
    mode = mode,
    documents = list(),
    similarity_matrix = NULL,
    differences = list(),
    similarities = list(),
    insights = character(),
    timestamp = Sys.time()
  )
  
  # Process all documents
  all_docs <- rbind(primary_doc, comparison_docs)
  results$documents <- apply(all_docs, 1, function(doc) {
    process_document_for_comparison(doc, mode)
  })
  
  # Calculate similarity matrix
  results$similarity_matrix <- calculate_similarity_matrix(results$documents, mode)
  
  # Identify differences and similarities
  comparison_analysis <- analyze_document_differences(results$documents, mode)
  results$differences <- comparison_analysis$differences
  results$similarities <- comparison_analysis$similarities
  
  # Calculate summary metrics
  results$similarity_score <- mean(results$similarity_matrix[1, -1], na.rm = TRUE)
  results$total_differences <- length(unlist(results$differences))
  results$common_elements <- length(results$similarities)
  
  # Generate insights
  results$insights <- generate_comparison_insights(results)
  
  log_event(paste("Document comparison completed:", length(results$documents), "documents analyzed"))
  
  return(results)
}

#' Process document for comparison analysis
#' @param doc Document row
#' @param mode Comparison mode
#' @return Processed document structure
process_document_for_comparison <- function(doc, mode) {
  
  # Extract content
  content <- doc$ementa %||% ""
  title <- doc$titulo %||% ""
  
  processed <- list(
    id = paste0("doc_", sample(1000:9999, 1)),
    title = title,
    type = doc$tipo,
    date = doc$data,
    state = doc$estado,
    content_raw = content,
    
    # Text processing
    content_normalized = normalize_text_for_comparison(content),
    word_count = str_count(content, "\\S+"),
    sentences = extract_sentences(content),
    
    # Structure analysis
    articles = extract_articles(content),
    paragraphs = extract_paragraphs(content),
    legal_references = extract_legal_references(content),
    
    # Semantic elements
    key_terms = extract_key_terms_for_comparison(content),
    themes = identify_document_themes(content),
    legal_concepts = extract_legal_concepts(content),
    
    # Metadata
    metadata = list(
      author = doc$autor,
      number = doc$numero,
      quality_score = doc$quality_score %||% 0,
      relevance = doc$relevancia_transporte %||% 0
    )
  )
  
  return(processed)
}

#' Normalize text for comparison
#' @param text Raw text
#' @return Normalized text
normalize_text_for_comparison <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return("")
  }
  
  normalized <- text %>%
    # Convert to lowercase
    str_to_lower() %>%
    # Remove extra whitespace
    str_squish() %>%
    # Remove special characters but keep sentence structure
    str_replace_all("[^a-záàâãéèêíìîóòôõúùûç0-9\\s\\.\\,\\;\\:]", "") %>%
    # Standardize legal patterns
    str_replace_all("artigo\\s+(\\d+)", "art. \\1") %>%
    str_replace_all("§\\s*(\\d+)", "§\\1") %>%
    # Remove excessive punctuation
    str_replace_all("[\\.]{2,}", ".") %>%
    str_replace_all("[\\,]{2,}", ",") %>%
    # Normalize spacing
    str_replace_all("\\s+", " ") %>%
    str_trim()
  
  return(normalized)
}

#' Extract sentences from text
#' @param text Document text
#' @return Vector of sentences
extract_sentences <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return(character(0))
  }
  
  sentences <- text %>%
    str_split("(?<=[.!?])\\s+") %>%
    unlist() %>%
    str_trim() %>%
    .[nchar(.) > 0]
  
  return(sentences)
}

#' Extract articles from legal text
#' @param text Document text
#' @return Vector of articles
extract_articles <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return(character(0))
  }
  
  # Find article patterns
  article_matches <- str_extract_all(text, "Art\\.?\\s*\\d+[^Art]*")[[1]]
  
  return(article_matches)
}

#' Extract paragraphs and sections
#' @param text Document text  
#' @return Vector of paragraphs
extract_paragraphs <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return(character(0))
  }
  
  # Find paragraph patterns
  paragraph_matches <- str_extract_all(text, "§\\s*\\d+[^§]*")[[1]]
  
  return(paragraph_matches)
}

#' Extract legal references
#' @param text Document text
#' @return Vector of legal references
extract_legal_references <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return(character(0))
  }
  
  # Legal reference patterns
  patterns <- c(
    "Lei\\s+n[º°]?\\s*[\\d\\.]+",
    "Decreto\\s+n[º°]?\\s*[\\d\\.]+",
    "Resolução\\s+n[º°]?\\s*[\\d\\.]+",
    "Portaria\\s+n[º°]?\\s*[\\d\\.]+"
  )
  
  references <- character(0)
  for (pattern in patterns) {
    matches <- str_extract_all(text, pattern, ignore.case = TRUE)[[1]]
    references <- c(references, matches)
  }
  
  return(unique(references))
}

#' Extract key terms for comparison
#' @param text Document text
#' @return Vector of key terms
extract_key_terms_for_comparison <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return(character(0))
  }
  
  # Transport and mobility terms
  transport_terms <- c(
    "transporte", "mobilidade", "trânsito", "viário", "rodoviário",
    "ônibus", "metrô", "trem", "bicicleta", "pedestre", "veículo",
    "estacionamento", "semáforo", "sinalização", "via", "avenida",
    "rodovia", "ciclovia", "passarela", "viaduto", "túnel"
  )
  
  # Legal terms
  legal_terms <- c(
    "lei", "decreto", "resolução", "portaria", "instrução",
    "norma", "regulamento", "código", "estatuto", "regimento"
  )
  
  # Administrative terms
  admin_terms <- c(
    "município", "estado", "federal", "público", "privado",
    "secretaria", "departamento", "autarquia", "empresa"
  )
  
  all_terms <- c(transport_terms, legal_terms, admin_terms)
  
  # Find terms in text
  text_lower <- str_to_lower(text)
  found_terms <- all_terms[sapply(all_terms, function(term) {
    str_detect(text_lower, paste0("\\b", term, "\\b"))
  })]
  
  return(found_terms)
}

#' Identify document themes
#' @param text Document text
#' @return Vector of themes
identify_document_themes <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return(character(0))
  }
  
  # Theme patterns
  themes <- list(
    "Transporte Público" = c("ônibus", "metrô", "trem", "transporte público", "coletivo"),
    "Trânsito" = c("trânsito", "sinalização", "semáforo", "velocidade", "multa"),
    "Infraestrutura" = c("via", "rodovia", "ponte", "viaduto", "túnel", "pavimentação"),
    "Mobilidade Urbana" = c("mobilidade", "urbana", "planejamento", "acessibilidade"),
    "Sustentabilidade" = c("bicicleta", "ciclovia", "pedestre", "ambiental", "poluição"),
    "Regulamentação" = c("licença", "permissão", "autorização", "fiscalização", "penalidade")
  )
  
  text_lower <- str_to_lower(text)
  found_themes <- character(0)
  
  for (theme_name in names(themes)) {
    theme_terms <- themes[[theme_name]]
    if (any(sapply(theme_terms, function(term) str_detect(text_lower, term)))) {
      found_themes <- c(found_themes, theme_name)
    }
  }
  
  return(found_themes)
}

#' Extract legal concepts
#' @param text Document text
#' @return Vector of legal concepts
extract_legal_concepts <- function(text) {
  if (is.null(text) || nchar(str_trim(text)) == 0) {
    return(character(0))
  }
  
  # Legal concept patterns
  concepts <- c(
    "competência", "atribuição", "responsabilidade", "obrigação",
    "direito", "dever", "proibição", "permissão", "autorização",
    "licença", "concessão", "penalidade", "multa", "infração",
    "recurso", "processo", "procedimento", "prazo", "termo"
  )
  
  text_lower <- str_to_lower(text)
  found_concepts <- concepts[sapply(concepts, function(concept) {
    str_detect(text_lower, paste0("\\b", concept, "\\b"))
  })]
  
  return(found_concepts)
}

#' Calculate similarity matrix between documents
#' @param documents List of processed documents
#' @param mode Comparison mode
#' @return Similarity matrix
calculate_similarity_matrix <- function(documents, mode) {
  
  n_docs <- length(documents)
  similarity_matrix <- matrix(0, nrow = n_docs, ncol = n_docs)
  
  for (i in 1:n_docs) {
    for (j in 1:n_docs) {
      if (i == j) {
        similarity_matrix[i, j] <- 1.0
      } else {
        similarity_matrix[i, j] <- calculate_document_similarity(
          documents[[i]], documents[[j]], mode
        )
      }
    }
  }
  
  return(similarity_matrix)
}

#' Calculate similarity between two documents
#' @param doc1 First document
#' @param doc2 Second document
#' @param mode Comparison mode
#' @return Similarity score (0-1)
calculate_document_similarity <- function(doc1, doc2, mode) {
  
  if (mode == "text") {
    # Text-based similarity using normalized content
    similarity <- calculate_text_similarity(doc1$content_normalized, doc2$content_normalized)
    
  } else if (mode == "structure") {
    # Structure-based similarity
    similarity <- calculate_structural_similarity(doc1, doc2)
    
  } else if (mode == "semantic") {
    # Semantic similarity using key terms and themes
    similarity <- calculate_semantic_similarity(doc1, doc2)
    
  } else if (mode == "metadata") {
    # Metadata-based similarity
    similarity <- calculate_metadata_similarity(doc1, doc2)
    
  } else {
    # Default to text similarity
    similarity <- calculate_text_similarity(doc1$content_normalized, doc2$content_normalized)
  }
  
  return(similarity)
}

#' Calculate text similarity using Jaccard index
#' @param text1 First text
#' @param text2 Second text
#' @return Similarity score
calculate_text_similarity <- function(text1, text2) {
  
  if (is.null(text1) || is.null(text2) || nchar(text1) == 0 || nchar(text2) == 0) {
    return(0)
  }
  
  # Tokenize texts
  words1 <- str_split(text1, "\\s+")[[1]]
  words2 <- str_split(text2, "\\s+")[[1]]
  
  # Calculate Jaccard similarity
  intersection <- length(intersect(words1, words2))
  union <- length(union(words1, words2))
  
  if (union == 0) return(0)
  
  jaccard_similarity <- intersection / union
  
  return(jaccard_similarity)
}

#' Calculate structural similarity
#' @param doc1 First document
#' @param doc2 Second document
#' @return Similarity score
calculate_structural_similarity <- function(doc1, doc2) {
  
  # Compare structural elements
  article_similarity <- jaccard_similarity(doc1$articles, doc2$articles)
  paragraph_similarity <- jaccard_similarity(doc1$paragraphs, doc2$paragraphs)
  reference_similarity <- jaccard_similarity(doc1$legal_references, doc2$legal_references)
  
  # Weighted average
  similarity <- (article_similarity * 0.4) + (paragraph_similarity * 0.3) + (reference_similarity * 0.3)
  
  return(similarity)
}

#' Calculate semantic similarity
#' @param doc1 First document
#' @param doc2 Second document
#' @return Similarity score
calculate_semantic_similarity <- function(doc1, doc2) {
  
  # Compare semantic elements
  terms_similarity <- jaccard_similarity(doc1$key_terms, doc2$key_terms)
  themes_similarity <- jaccard_similarity(doc1$themes, doc2$themes)
  concepts_similarity <- jaccard_similarity(doc1$legal_concepts, doc2$legal_concepts)
  
  # Weighted average
  similarity <- (terms_similarity * 0.4) + (themes_similarity * 0.35) + (concepts_similarity * 0.25)
  
  return(similarity)
}

#' Calculate metadata similarity
#' @param doc1 First document
#' @param doc2 Second document
#' @return Similarity score
calculate_metadata_similarity <- function(doc1, doc2) {
  
  similarity <- 0
  
  # Document type
  if (doc1$type == doc2$type) similarity <- similarity + 0.3
  
  # State
  if (doc1$state == doc2$state) similarity <- similarity + 0.2
  
  # Date proximity (within 1 year = 0.2, within 5 years = 0.1)
  date1 <- as.Date(doc1$date)
  date2 <- as.Date(doc2$date)
  if (!is.na(date1) && !is.na(date2)) {
    date_diff <- abs(as.numeric(date1 - date2))
    if (date_diff <= 365) similarity <- similarity + 0.2
    else if (date_diff <= 1825) similarity <- similarity + 0.1
  }
  
  # Quality score proximity
  if (!is.null(doc1$metadata$quality_score) && !is.null(doc2$metadata$quality_score)) {
    quality_diff <- abs(doc1$metadata$quality_score - doc2$metadata$quality_score)
    quality_similarity <- max(0, 1 - (quality_diff / 100))
    similarity <- similarity + (quality_similarity * 0.15)
  }
  
  # Relevance proximity
  if (!is.null(doc1$metadata$relevance) && !is.null(doc2$metadata$relevance)) {
    relevance_diff <- abs(doc1$metadata$relevance - doc2$metadata$relevance)
    relevance_similarity <- max(0, 1 - (relevance_diff / 100))
    similarity <- similarity + (relevance_similarity * 0.15)
  }
  
  return(min(similarity, 1.0))
}

#' Helper function for Jaccard similarity
#' @param set1 First set
#' @param set2 Second set
#' @return Jaccard similarity
jaccard_similarity <- function(set1, set2) {
  if (length(set1) == 0 && length(set2) == 0) return(1.0)
  if (length(set1) == 0 || length(set2) == 0) return(0.0)
  
  intersection <- length(intersect(set1, set2))
  union <- length(union(set1, set2))
  
  return(intersection / union)
}

#' Analyze differences between documents
#' @param documents List of processed documents
#' @param mode Comparison mode
#' @return Analysis results
analyze_document_differences <- function(documents, mode) {
  
  primary_doc <- documents[[1]]
  comparison_docs <- documents[-1]
  
  differences <- list()
  similarities <- list()
  
  for (i in seq_along(comparison_docs)) {
    comp_doc <- comparison_docs[[i]]
    
    # Find differences based on mode
    if (mode == "text") {
      diff_result <- find_text_differences(primary_doc, comp_doc)
    } else if (mode == "structure") {
      diff_result <- find_structural_differences(primary_doc, comp_doc)
    } else if (mode == "semantic") {
      diff_result <- find_semantic_differences(primary_doc, comp_doc)
    } else {
      diff_result <- find_text_differences(primary_doc, comp_doc)
    }
    
    differences[[i]] <- diff_result$differences
    similarities[[i]] <- diff_result$similarities
  }
  
  return(list(differences = differences, similarities = similarities))
}

#' Find text differences between documents
#' @param doc1 Primary document
#' @param doc2 Comparison document
#' @return Differences and similarities
find_text_differences <- function(doc1, doc2) {
  
  # Compare sentences
  sentences1 <- doc1$sentences
  sentences2 <- doc2$sentences
  
  # Find unique sentences
  unique_to_doc1 <- setdiff(sentences1, sentences2)
  unique_to_doc2 <- setdiff(sentences2, sentences1)
  common_sentences <- intersect(sentences1, sentences2)
  
  differences <- list(
    unique_to_primary = unique_to_doc1,
    unique_to_comparison = unique_to_doc2,
    type = "text"
  )
  
  similarities <- list(
    common_sentences = common_sentences,
    type = "text"
  )
  
  return(list(differences = differences, similarities = similarities))
}

#' Find structural differences
#' @param doc1 Primary document
#' @param doc2 Comparison document
#' @return Differences and similarities
find_structural_differences <- function(doc1, doc2) {
  
  differences <- list(
    articles_unique_to_primary = setdiff(doc1$articles, doc2$articles),
    articles_unique_to_comparison = setdiff(doc2$articles, doc1$articles),
    paragraphs_unique_to_primary = setdiff(doc1$paragraphs, doc2$paragraphs),
    paragraphs_unique_to_comparison = setdiff(doc2$paragraphs, doc1$paragraphs),
    type = "structure"
  )
  
  similarities <- list(
    common_articles = intersect(doc1$articles, doc2$articles),
    common_paragraphs = intersect(doc1$paragraphs, doc2$paragraphs),
    common_references = intersect(doc1$legal_references, doc2$legal_references),
    type = "structure"
  )
  
  return(list(differences = differences, similarities = similarities))
}

#' Find semantic differences
#' @param doc1 Primary document
#' @param doc2 Comparison document
#' @return Differences and similarities
find_semantic_differences <- function(doc1, doc2) {
  
  differences <- list(
    themes_unique_to_primary = setdiff(doc1$themes, doc2$themes),
    themes_unique_to_comparison = setdiff(doc2$themes, doc1$themes),
    terms_unique_to_primary = setdiff(doc1$key_terms, doc2$key_terms),
    terms_unique_to_comparison = setdiff(doc2$key_terms, doc1$key_terms),
    type = "semantic"
  )
  
  similarities <- list(
    common_themes = intersect(doc1$themes, doc2$themes),
    common_terms = intersect(doc1$key_terms, doc2$key_terms),
    common_concepts = intersect(doc1$legal_concepts, doc2$legal_concepts),
    type = "semantic"
  )
  
  return(list(differences = differences, similarities = similarities))
}

#' Generate comparison insights
#' @param results Comparison results
#' @return Vector of insights
generate_comparison_insights <- function(results) {
  
  insights <- character(0)
  
  # Similarity insights
  avg_similarity <- results$similarity_score
  if (avg_similarity > 0.8) {
    insights <- c(insights, "Documentos apresentam alta similaridade, indicando possível complementaridade ou redundância")
  } else if (avg_similarity > 0.5) {
    insights <- c(insights, "Documentos possuem similaridade moderada, com temas relacionados mas abordagens distintas")
  } else if (avg_similarity < 0.3) {
    insights <- c(insights, "Documentos apresentam baixa similaridade, tratando de aspectos diferentes da legislação")
  }
  
  # Document type analysis
  doc_types <- sapply(results$documents, function(d) d$type)
  unique_types <- unique(doc_types)
  if (length(unique_types) == 1) {
    insights <- c(insights, paste("Todos os documentos são do tipo", unique_types[1]))
  } else {
    insights <- c(insights, paste("Comparação entre", length(unique_types), "tipos diferentes de documentos"))
  }
  
  # Temporal analysis
  dates <- sapply(results$documents, function(d) as.Date(d$date))
  date_range <- max(dates, na.rm = TRUE) - min(dates, na.rm = TRUE)
  if (date_range > 365 * 5) {
    insights <- c(insights, "Documentos abrangem um período extenso, mostrando evolução temporal da legislação")
  } else if (date_range <= 365) {
    insights <- c(insights, "Documentos são contemporâneos, possivelmente parte de um pacote legislativo")
  }
  
  # Geographic insights
  states <- sapply(results$documents, function(d) d$state)
  unique_states <- unique(states[!is.na(states)])
  if (length(unique_states) == 1) {
    insights <- c(insights, paste("Todos os documentos são do estado de", unique_states[1]))
  } else if (length(unique_states) > 3) {
    insights <- c(insights, "Comparação entre documentos de múltiplos estados, indicando abrangência nacional")
  }
  
  return(insights)
}

#' Create side-by-side comparison view
#' @param results Comparison results
#' @return HTML content
create_side_by_side_comparison <- function(results) {
  
  primary_doc <- results$documents[[1]]
  comparison_docs <- results$documents[-1]
  
  # Create columns for each document
  column_width <- 12 / (length(comparison_docs) + 1)
  
  div(
    class = "side-by-side-container",
    
    fluidRow(
      # Primary document column
      column(column_width,
        div(
          class = "document-column primary-doc",
          style = "border-right: 1px solid #dee2e6; padding-right: 15px;",
          
          h5("📄 Documento Principal", class = "text-primary mb-3"),
          
          div(
            class = "document-header mb-3 p-2 bg-light rounded",
            strong(str_trunc(primary_doc$title, 50)),
            br(),
            span(paste(primary_doc$type, "-", primary_doc$state), class = "text-muted"),
            br(),
            span(format(as.Date(primary_doc$date), "%d/%m/%Y"), class = "text-muted")
          ),
          
          div(
            class = "document-content",
            style = "height: 400px; overflow-y: auto; border: 1px solid #dee2e6; padding: 10px; background: white;",
            p(primary_doc$content_raw)
          )
        )
      ),
      
      # Comparison document columns
      lapply(seq_along(comparison_docs), function(i) {
        comp_doc <- comparison_docs[[i]]
        similarity <- results$similarity_matrix[1, i + 1]
        
        column(column_width,
          div(
            class = "document-column comparison-doc",
            style = if (i < length(comparison_docs)) "border-right: 1px solid #dee2e6; padding-right: 15px;" else "",
            
            h5(paste("📑 Documento", i), class = "text-info mb-3"),
            
            div(
              class = "document-header mb-3 p-2 bg-light rounded",
              strong(str_trunc(comp_doc$title, 50)),
              br(),
              span(paste(comp_doc$type, "-", comp_doc$state), class = "text-muted"),
              br(),
              span(format(as.Date(comp_doc$date), "%d/%m/%Y"), class = "text-muted"),
              br(),
              span(paste("Similaridade:", paste0(round(similarity * 100), "%")), 
                   class = paste("badge", if (similarity > 0.7) "bg-success" else if (similarity > 0.4) "bg-warning" else "bg-danger"))
            ),
            
            div(
              class = "document-content",
              style = "height: 400px; overflow-y: auto; border: 1px solid #dee2e6; padding: 10px; background: white;",
              p(comp_doc$content_raw)
            )
          )
        )
      })
    )
  )
}

#' Create diff highlighted view
#' @param results Comparison results
#' @return HTML content
create_diff_highlighted_view <- function(results) {
  
  div(
    class = "diff-highlighted-container",
    
    h5("🔍 Diferenças Destacadas", class = "mb-3"),
    
    # Differences for each comparison
    lapply(seq_along(results$differences), function(i) {
      differences <- results$differences[[i]]
      
      div(
        class = paste("comparison-diff mb-4 p-3 border rounded"),
        
        h6(paste("Comparação com Documento", i), class = "text-info mb-3"),
        
        if (differences$type == "text") {
          div(
            class = "text-differences",
            
            if (length(differences$unique_to_primary) > 0) {
              div(
                class = "unique-to-primary mb-3",
                h6("🟢 Único no Documento Principal:", class = "text-success"),
                div(
                  class = "unique-content p-2 rounded",
                  style = paste("background:", COMPARISON_CONFIG$highlight_colors$added),
                  lapply(differences$unique_to_primary[1:min(3, length(differences$unique_to_primary))], function(sentence) {
                    p(sentence, class = "mb-1")
                  })
                )
              )
            },
            
            if (length(differences$unique_to_comparison) > 0) {
              div(
                class = "unique-to-comparison mb-3",
                h6("🔴 Único no Documento Comparado:", class = "text-danger"),
                div(
                  class = "unique-content p-2 rounded",
                  style = paste("background:", COMPARISON_CONFIG$highlight_colors$removed),
                  lapply(differences$unique_to_comparison[1:min(3, length(differences$unique_to_comparison))], function(sentence) {
                    p(sentence, class = "mb-1")
                  })
                )
              )
            }
          )
        } else if (differences$type == "structure") {
          div(
            class = "structural-differences",
            
            if (length(differences$articles_unique_to_primary) > 0) {
              div(
                class = "mb-2",
                strong("Artigos únicos no principal: "),
                span(paste(length(differences$articles_unique_to_primary), "encontrados"))
              )
            },
            
            if (length(differences$articles_unique_to_comparison) > 0) {
              div(
                class = "mb-2",
                strong("Artigos únicos na comparação: "),
                span(paste(length(differences$articles_unique_to_comparison), "encontrados"))
              )
            )
          )
        } else if (differences$type == "semantic") {
          div(
            class = "semantic-differences",
            
            if (length(differences$themes_unique_to_primary) > 0) {
              div(
                class = "mb-2",
                strong("Temas únicos no principal: "),
                span(paste(differences$themes_unique_to_primary, collapse = ", "))
              )
            ),
            
            if (length(differences$themes_unique_to_comparison) > 0) {
              div(
                class = "mb-2",
                strong("Temas únicos na comparação: "),
                span(paste(differences$themes_unique_to_comparison, collapse = ", "))
              )
            )
          )
        }
      )
    })
  )
}

#' Create statistical analysis view
#' @param results Comparison results
#' @return HTML content
create_statistical_analysis <- function(results) {
  
  # Calculate statistics
  similarity_matrix <- results$similarity_matrix
  avg_similarity <- mean(similarity_matrix[1, -1], na.rm = TRUE)
  max_similarity <- max(similarity_matrix[1, -1], na.rm = TRUE)
  min_similarity <- min(similarity_matrix[1, -1], na.rm = TRUE)
  
  # Document statistics
  word_counts <- sapply(results$documents, function(d) d$word_count)
  sentence_counts <- sapply(results$documents, function(d) length(d$sentences))
  
  div(
    class = "statistical-analysis-container",
    
    h5("📊 Análise Estatística", class = "mb-4"),
    
    # Summary metrics
    div(
      class = "metrics-grid mb-4",
      style = "display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;",
      
      div(
        class = "metric-card p-3 border rounded text-center",
        h4(paste0(round(avg_similarity * 100), "%"), class = "text-primary mb-1"),
        p("Similaridade Média", class = "text-muted mb-0")
      ),
      
      div(
        class = "metric-card p-3 border rounded text-center",
        h4(paste0(round(max_similarity * 100), "%"), class = "text-success mb-1"),
        p("Maior Similaridade", class = "text-muted mb-0")
      ),
      
      div(
        class = "metric-card p-3 border rounded text-center",
        h4(paste0(round(min_similarity * 100), "%"), class = "text-warning mb-1"),
        p("Menor Similaridade", class = "text-muted mb-0")
      ),
      
      div(
        class = "metric-card p-3 border rounded text-center",
        h4(length(results$documents), class = "text-info mb-1"),
        p("Total de Documentos", class = "text-muted mb-0")
      )
    ),
    
    # Document characteristics
    div(
      class = "document-characteristics mb-4",
      h6("📋 Características dos Documentos"),
      
      div(
        class = "table-responsive",
        tags$table(
          class = "table table-sm table-striped",
          tags$thead(
            tags$tr(
              tags$th("Documento"),
              tags$th("Palavras"),
              tags$th("Sentenças"),
              tags$th("Temas"),
              tags$th("Tipo")
            )
          ),
          tags$tbody(
            lapply(seq_along(results$documents), function(i) {
              doc <- results$documents[[i]]
              doc_name <- if (i == 1) "Principal" else paste("Comparação", i - 1)
              
              tags$tr(
                tags$td(doc_name),
                tags$td(format(doc$word_count, big.mark = ".")),
                tags$td(length(doc$sentences)),
                tags$td(length(doc$themes)),
                tags$td(doc$type)
              )
            })
          )
        )
      )
    ),
    
    # Similarity matrix visualization
    div(
      class = "similarity-matrix mb-4",
      h6("🔗 Matriz de Similaridade"),
      
      div(
        class = "table-responsive",
        tags$table(
          class = "table table-sm table-bordered text-center",
          tags$thead(
            tags$tr(
              tags$th(""),
              lapply(seq_along(results$documents), function(i) {
                doc_name <- if (i == 1) "Principal" else paste("Doc", i - 1)
                tags$th(doc_name)
              })
            )
          ),
          tags$tbody(
            lapply(seq_along(results$documents), function(i) {
              doc_name <- if (i == 1) "Principal" else paste("Doc", i - 1)
              
              tags$tr(
                tags$th(doc_name),
                lapply(seq_along(results$documents), function(j) {
                  similarity <- similarity_matrix[i, j]
                  color_class <- if (similarity > 0.7) "table-success" 
                               else if (similarity > 0.4) "table-warning" 
                               else if (similarity > 0.1) "table-danger"
                               else ""
                  
                  tags$td(
                    paste0(round(similarity * 100), "%"),
                    class = color_class
                  )
                })
              )
            })
          )
        )
      )
    )
  )
}

#' Create structural comparison view
#' @param results Comparison results
#' @return HTML content
create_structural_comparison <- function(results) {
  
  div(
    class = "structural-comparison-container",
    
    h5("🏗️ Comparação Estrutural", class = "mb-4"),
    
    # Structure overview
    div(
      class = "structure-overview mb-4",
      
      div(
        class = "row",
        
        lapply(seq_along(results$documents), function(i) {
          doc <- results$documents[[i]]
          doc_name <- if (i == 1) "Principal" else paste("Documento", i - 1)
          
          column(12 / length(results$documents),
            div(
              class = "structure-card p-3 border rounded",
              
              h6(doc_name, class = if (i == 1) "text-primary" else "text-info"),
              
              div(
                class = "structure-metrics",
                p(paste("📋 Artigos:", length(doc$articles)), class = "mb-1"),
                p(paste("📄 Parágrafos:", length(doc$paragraphs)), class = "mb-1"),
                p(paste("🔗 Referências:", length(doc$legal_references)), class = "mb-1"),
                p(paste("🏷️ Conceitos:", length(doc$legal_concepts)), class = "mb-1")
              )
            )
          )
        })
      )
    ),
    
    # Detailed structural analysis
    div(
      class = "detailed-structure mb-4",
      
      h6("📖 Elementos Estruturais Detalhados"),
      
      navset_card_tab(
        nav_panel(
          "Artigos",
          if (any(sapply(results$documents, function(d) length(d$articles) > 0))) {
            div(
              class = "articles-comparison",
              lapply(seq_along(results$documents), function(i) {
                doc <- results$documents[[i]]
                if (length(doc$articles) > 0) {
                  div(
                    class = "document-articles mb-3",
                    h6(paste("Documento", if (i == 1) "Principal" else i - 1), class = "text-muted"),
                    div(
                      class = "articles-list",
                      style = "max-height: 200px; overflow-y: auto;",
                      lapply(doc$articles[1:min(5, length(doc$articles))], function(article) {
                        p(str_trunc(article, 100), class = "small mb-1")
                      })
                    )
                  )
                }
              })
            )
          } else {
            p("Nenhum artigo identificado nos documentos", class = "text-muted")
          }
        ),
        
        nav_panel(
          "Referências Legais",
          if (any(sapply(results$documents, function(d) length(d$legal_references) > 0))) {
            div(
              class = "references-comparison",
              lapply(seq_along(results$documents), function(i) {
                doc <- results$documents[[i]]
                if (length(doc$legal_references) > 0) {
                  div(
                    class = "document-references mb-3",
                    h6(paste("Documento", if (i == 1) "Principal" else i - 1), class = "text-muted"),
                    div(
                      class = "references-list",
                      lapply(doc$legal_references, function(ref) {
                        span(ref, class = "badge bg-secondary me-1 mb-1")
                      })
                    )
                  )
                }
              })
            )
          } else {
            p("Nenhuma referência legal identificada", class = "text-muted")
          }
        ),
        
        nav_panel(
          "Conceitos Jurídicos",
          if (any(sapply(results$documents, function(d) length(d$legal_concepts) > 0))) {
            div(
              class = "concepts-comparison",
              lapply(seq_along(results$documents), function(i) {
                doc <- results$documents[[i]]
                if (length(doc$legal_concepts) > 0) {
                  div(
                    class = "document-concepts mb-3",
                    h6(paste("Documento", if (i == 1) "Principal" else i - 1), class = "text-muted"),
                    div(
                      class = "concepts-list",
                      lapply(doc$legal_concepts, function(concept) {
                        span(concept, class = "badge bg-info me-1 mb-1")
                      })
                    )
                  )
                }
              })
            )
          } else {
            p("Nenhum conceito jurídico específico identificado", class = "text-muted")
          }
        )
      )
    )
  )
}

#' Generate comparison report for export
#' @param results Comparison results
#' @param format Export format
#' @return File path to generated report
generate_comparison_report <- function(results, format = "html") {
  
  tryCatch({
    
    if (format == "html") {
      temp_file <- tempfile(fileext = ".html")
      
      # Generate HTML report
      html_content <- create_html_comparison_report(results)
      
      writeLines(html_content, temp_file)
      
      log_event("Comparison report generated successfully")
      return(temp_file)
    }
    
    return(NULL)
    
  }, error = function(e) {
    log_event(paste("Error generating comparison report:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create HTML comparison report
#' @param results Comparison results
#' @return HTML content string
create_html_comparison_report <- function(results) {
  
  primary_doc <- results$documents[[1]]
  
  html_content <- paste0(
    "<!DOCTYPE html>",
    "<html lang='pt-BR'>",
    "<head>",
    "<meta charset='UTF-8'>",
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
    "<title>Relatório de Comparação de Documentos Legislativos</title>",
    "<style>",
    "body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }",
    ".header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }",
    ".metric { display: inline-block; margin: 10px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; text-align: center; }",
    ".document { margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }",
    ".similarity-high { background: #d4edda; }",
    ".similarity-medium { background: #fff3cd; }",
    ".similarity-low { background: #f8d7da; }",
    "</style>",
    "</head>",
    "<body>",
    
    # Header
    "<div class='header'>",
    "<h1>📊 Relatório de Comparação de Documentos Legislativos</h1>",
    "<p><strong>Gerado em:</strong> ", format(Sys.time(), "%d de %B de %Y às %H:%M"), "</p>",
    "<p><strong>Documento Principal:</strong> ", htmlEscape(primary_doc$title), "</p>",
    "<p><strong>Modo de Comparação:</strong> ", results$mode, "</p>",
    "</div>",
    
    # Summary metrics
    "<div class='summary'>",
    "<h2>📈 Resumo da Análise</h2>",
    "<div class='metric'>",
    "<h3>", length(results$documents), "</h3>",
    "<p>Documentos Analisados</p>",
    "</div>",
    "<div class='metric'>",
    "<h3>", paste0(round(results$similarity_score * 100), "%"), "</h3>",
    "<p>Similaridade Média</p>",
    "</div>",
    "<div class='metric'>",
    "<h3>", results$total_differences, "</h3>",
    "<p>Diferenças Encontradas</p>",
    "</div>",
    "</div>",
    
    # Documents details
    "<div class='documents'>",
    "<h2>📄 Documentos Comparados</h2>",
    paste0(lapply(seq_along(results$documents), function(i) {
      doc <- results$documents[[i]]
      similarity <- if (i == 1) 1.0 else results$similarity_matrix[1, i]
      similarity_class <- if (similarity > 0.7) "similarity-high" 
                         else if (similarity > 0.4) "similarity-medium" 
                         else "similarity-low"
      
      paste0(
        "<div class='document ", similarity_class, "'>",
        "<h3>", if (i == 1) "📄 Documento Principal" else paste("📑 Documento", i - 1), "</h3>",
        "<p><strong>Título:</strong> ", htmlEscape(doc$title), "</p>",
        "<p><strong>Tipo:</strong> ", doc$type, "</p>",
        "<p><strong>Data:</strong> ", format(as.Date(doc$date), "%d/%m/%Y"), "</p>",
        "<p><strong>Estado:</strong> ", doc$state, "</p>",
        if (i > 1) paste0("<p><strong>Similaridade:</strong> ", round(similarity * 100), "%</p>") else "",
        "<p><strong>Palavras:</strong> ", format(doc$word_count, big.mark = "."), "</p>",
        "<p><strong>Temas:</strong> ", paste(doc$themes, collapse = ", "), "</p>",
        "</div>"
      )
    }), collapse = ""),
    "</div>",
    
    # Insights
    "<div class='insights'>",
    "<h2>💡 Principais Insights</h2>",
    "<ul>",
    paste0(lapply(results$insights, function(insight) {
      paste0("<li>", insight, "</li>")
    }), collapse = ""),
    "</ul>",
    "</div>",
    
    # Footer
    "<div class='footer' style='margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;'>",
    "<p>Relatório gerado pelo Monitor Legislativo v4 - Plataforma de Análise de Documentos Legislativos</p>",
    "</div>",
    
    "</body>",
    "</html>"
  )
  
  return(html_content)
}

#' Helper function for string truncation
str_trunc <- function(string, width) {
  if (is.na(string) || nchar(string) <= width) {
    return(string)
  }
  paste0(substr(string, 1, width - 3), "...")
}

#' Helper function for HTML escaping
htmlEscape <- function(text) {
  htmltools::htmlEscape(text)
}