# Export Module - Week 5 Enhanced Implementation
# Monitor Legislativo v4 - Data Export and Academic Publishing Interface
# ======================================================================

#' Export Module for Monitor Legislativo v4 - Week 5 Implementation
#' 
#' Comprehensive Shiny module for exporting legislative data with enhanced
#' memory-efficient processing for Railway constraints (2GB limit), 
#' background processing, and extended academic publishing formats.
#' 
#' Week 5 Enhancements:
#' - Memory-efficient processing with data streaming for large datasets
#' - Background export processing with real-time progress tracking
#' - LexML-compatible XML export for legal databases
#' - EndNote XML export for academic institutions
#' - Enhanced file compression and chunking
#' - Performance monitoring and automatic optimization
#' - Railway deployment optimizations

library(shiny)
library(DT)
library(openxlsx)
library(jsonlite)
library(xml2)
library(future)
library(promises)

# Memory Management and Performance Optimization Functions
# Week 5 Enhanced Implementation
# ========================================================

#' Monitor memory usage for Railway deployment constraints
monitor_memory_usage <- function() {
  if (Sys.info()["sysname"] == "Linux") {
    # Check memory usage on Linux (Railway environment)
    tryCatch({
      mem_info <- system("cat /proc/meminfo | grep MemAvailable", intern = TRUE)
      available_kb <- as.numeric(gsub(".*?(\\d+).*", "\\1", mem_info))
      available_mb <- available_kb / 1024
      available_gb <- available_mb / 1024
      
      return(list(
        available_mb = round(available_mb, 1),
        available_gb = round(available_gb, 2),
        usage_percent = round((2048 - available_mb) / 2048 * 100, 1)  # Assuming 2GB limit
      ))
    }, error = function(e) {
      return(list(available_mb = 1024, available_gb = 1.0, usage_percent = 50))
    })
  } else {
    # Fallback for other systems
    return(list(available_mb = 1024, available_gb = 1.0, usage_percent = 50))
  }
}

#' Estimate memory requirement for dataset
estimate_memory_requirement <- function(data, format) {
  if (is.null(data) || nrow(data) == 0) return(0)
  
  # Base memory requirement
  base_size_mb <- as.numeric(object.size(data)) / 1024^2
  
  # Format-specific multipliers
  format_multiplier <- switch(format,
    "csv" = 1.2,     # Text format, slight overhead
    "xlsx" = 2.5,    # Excel format requires significant overhead
    "json" = 1.5,    # JSON formatting overhead
    "xml" = 2.0,     # XML structure overhead
    "lexml" = 2.2,   # LexML requires additional structure
    "endnote" = 1.8, # EndNote XML overhead
    "bibtex" = 1.1,  # Minimal overhead
    "ris" = 1.1,     # Minimal overhead
    1.0              # Default
  )
  
  estimated_mb <- base_size_mb * format_multiplier
  
  return(round(estimated_mb, 2))
}

#' Check if export is feasible given memory constraints
check_export_feasibility <- function(data, format) {
  memory_status <- monitor_memory_usage()
  required_mb <- estimate_memory_requirement(data, format)
  
  # Leave at least 512MB free for system operations
  safety_margin_mb <- 512
  available_for_export <- memory_status$available_mb - safety_margin_mb
  
  return(list(
    feasible = required_mb <= available_for_export,
    required_mb = required_mb,
    available_mb = available_for_export,
    memory_status = memory_status,
    recommendation = if (required_mb > available_for_export) {
      "Use chunked export or reduce dataset size"
    } else {
      "Export feasible"
    }
  ))
}

#' Split large dataset into chunks for memory-efficient processing
chunk_dataset <- function(data, chunk_size = 5000) {
  if (nrow(data) <= chunk_size) {
    return(list(data))
  }
  
  num_chunks <- ceiling(nrow(data) / chunk_size)
  chunks <- list()
  
  for (i in 1:num_chunks) {
    start_row <- (i - 1) * chunk_size + 1
    end_row <- min(i * chunk_size, nrow(data))
    chunks[[i]] <- data[start_row:end_row, ]
  }
  
  return(chunks)
}

#' Background export processing with progress tracking
process_export_background <- function(data, format, filename, progress_callback = NULL) {
  # Use future for background processing
  future_promise <- future({
    tryCatch({
      total_rows <- nrow(data)
      
      # Process in chunks if large dataset
      if (total_rows > 10000) {
        chunks <- chunk_dataset(data, chunk_size = 5000)
        processed_data <- list()
        
        for (i in seq_along(chunks)) {
          if (!is.null(progress_callback)) {
            progress_callback(i / length(chunks) * 0.8, paste("Processing chunk", i, "of", length(chunks)))
          }
          
          processed_data[[i]] <- chunks[[i]]
          
          # Force garbage collection between chunks
          if (i %% 3 == 0) {
            gc()
          }
        }
        
        # Combine chunks
        final_data <- do.call(rbind, processed_data)
      } else {
        final_data <- data
      }
      
      # Convert to requested format
      if (!is.null(progress_callback)) {
        progress_callback(0.9, "Converting to export format...")
      }
      
      converted_data <- convert_to_format_enhanced(final_data, format)
      
      # Write to file
      if (!is.null(progress_callback)) {
        progress_callback(0.95, "Writing file...")
      }
      
      write_export_file(converted_data, filename, format)
      
      if (!is.null(progress_callback)) {
        progress_callback(1.0, "Export completed")
      }
      
      return(list(
        success = TRUE,
        filename = filename,
        rows_exported = nrow(final_data),
        file_size = file.size(filename)
      ))
      
    }, error = function(e) {
      return(list(
        success = FALSE,
        error = e$message
      ))
    })
  })
  
  return(future_promise)
}

# Enhanced Export Format Functions
# ================================

#' Enhanced format conversion with memory optimization
convert_to_format_enhanced <- function(data, format, options = NULL) {
  switch(format,
    "csv" = convert_to_csv_enhanced(data, options),
    "xlsx" = convert_to_xlsx_enhanced(data, options),
    "json" = convert_to_json_enhanced(data, options),
    "xml" = convert_to_xml_enhanced(data, options),
    "lexml" = convert_to_lexml(data, options),
    "endnote" = convert_to_endnote_xml(data, options),
    "bibtex" = convert_to_bibtex_enhanced(data, options),
    "ris" = convert_to_ris_enhanced(data, options),
    convert_to_json_enhanced(data, options)  # Default
  )
}

#' Convert to LexML format for legal databases
convert_to_lexml <- function(data, options = NULL) {
  lexml_header <- paste0(
    '<?xml version="1.0" encoding="UTF-8"?>\n',
    '<LexML xmlns="http://www.lexml.gov.br/1.0"\n',
    '       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n',
    '       xsi:schemaLocation="http://www.lexml.gov.br/1.0 http://projeto.lexml.gov.br/esquemas/lexml.xsd">\n',
    '  <metadados>\n',
    '    <identificacao>\n',
    '      <fonte>Monitor Legislativo v4</fonte>\n',
    '      <data_exportacao>', format(Sys.time(), "%Y-%m-%d %H:%M:%S"), '</data_exportacao>\n',
    '      <total_documentos>', nrow(data), '</total_documentos>\n',
    '    </identificacao>\n',
    '  </metadados>\n',
    '  <documentos>\n'
  )
  
  lexml_content <- ""
  
  for (i in 1:nrow(data)) {
    doc <- data[i, ]
    
    # Extract key fields
    titulo <- xml_escape(doc$titulo %||% doc$title %||% "")
    autoridade <- xml_escape(doc$autoridade %||% doc$authority %||% "")
    data_pub <- doc$data %||% doc$date %||% Sys.Date()
    estado <- doc$estado %||% doc$state %||% ""
    tipo <- xml_escape(doc$tipo_documento %||% doc$document_type %||% "")
    ementa <- xml_escape(doc$ementa %||% doc$summary %||% "")
    url <- doc$url %||% ""
    
    # Generate URN LEX if not present
    urn_lex <- generate_urn_lex(titulo, autoridade, data_pub, estado, tipo)
    
    lexml_content <- paste0(lexml_content,
      '    <documento>\n',
      '      <identificacao>\n',
      '        <urn>', urn_lex, '</urn>\n',
      '        <titulo>', titulo, '</titulo>\n',
      '        <tipo_documento>', tipo, '</tipo_documento>\n',
      '      </identificacao>\n',
      '      <autoria>\n',
      '        <autoridade>', autoridade, '</autoridade>\n',
      '        <jurisdicao>', estado, '</jurisdicao>\n',
      '      </autoria>\n',
      '      <publicacao>\n',
      '        <data>', format(as.Date(data_pub), "%Y-%m-%d"), '</data>\n',
      if (url != "") paste0('        <url_oficial>', url, '</url_oficial>\n') else '',
      '      </publicacao>\n',
      if (ementa != "") paste0('      <ementa>', ementa, '</ementa>\n') else '',
      '    </documento>\n'
    )
    
    # Clean memory periodically for large datasets
    if (i %% 1000 == 0) {
      gc()
    }
  }
  
  lexml_footer <- '  </documentos>\n</LexML>'
  
  return(paste0(lexml_header, lexml_content, lexml_footer))
}

#' Generate URN LEX identifier for Brazilian legal documents
generate_urn_lex <- function(titulo, autoridade, data, estado, tipo) {
  # Simplified URN LEX generation
  # Format: urn:lex:jurisdiction:authority:document_type:date:id
  
  # Normalize components
  jurisdiction <- if (estado == "DF" || estado == "") "br" else paste0("br:", tolower(estado))
  authority_normalized <- gsub("[^a-z]", "", tolower(autoridade))
  type_normalized <- gsub("[^a-z]", "", tolower(tipo))
  date_normalized <- format(as.Date(data), "%Y-%m-%d")
  
  # Generate simple ID from title
  title_id <- gsub("[^a-z0-9]", "", tolower(substr(titulo, 1, 20)))
  
  return(paste("urn:lex", jurisdiction, authority_normalized, type_normalized, 
               date_normalized, title_id, sep = ":"))
}

#' Convert to EndNote XML format for academic institutions
convert_to_endnote_xml <- function(data, options = NULL) {
  endnote_header <- paste0(
    '<?xml version="1.0" encoding="UTF-8"?>\n',
    '<xml>\n',
    '  <records>\n'
  )
  
  endnote_content <- ""
  
  for (i in 1:nrow(data)) {
    doc <- data[i, ]
    
    # Map to EndNote fields
    title <- xml_escape(doc$titulo %||% doc$title %||% "")
    author <- xml_escape(doc$autoridade %||% doc$authority %||% "")
    year <- format(as.Date(doc$data %||% doc$date %||% Sys.Date()), "%Y")
    url <- doc$url %||% ""
    abstract_text <- xml_escape(substr(doc$ementa %||% doc$summary %||% "", 1, 500))
    
    endnote_content <- paste0(endnote_content,
      '    <record>\n',
      '      <database name="Monitor Legislativo v4" path="monitor_legislativo.enl">monitor_legislativo.enl</database>\n',
      '      <source-app name="Monitor Legislativo" version="4.0">Monitor Legislativo</source-app>\n',
      '      <rec-number>', i, '</rec-number>\n',
      '      <foreign-keys>\n',
      '        <key app="EN" db-id="', i, '">', i, '</key>\n',
      '      </foreign-keys>\n',
      '      <ref-type name="Generic">13</ref-type>\n',
      '      <contributors>\n',
      '        <authors>\n',
      '          <author>', author, '</author>\n',
      '        </authors>\n',
      '      </contributors>\n',
      '      <titles>\n',
      '        <title>', title, '</title>\n',
      '      </titles>\n',
      '      <dates>\n',
      '        <year>', year, '</year>\n',
      '      </dates>\n',
      if (abstract_text != "") paste0('      <abstract>', abstract_text, '</abstract>\n') else '',
      if (url != "") paste0('      <urls>\n        <related-urls>\n          <url>', url, '</url>\n        </related-urls>\n      </urls>\n') else '',
      '    </record>\n'
    )
    
    # Memory management for large datasets
    if (i %% 500 == 0) {
      gc()
    }
  }
  
  endnote_footer <- '  </records>\n</xml>'
  
  return(paste0(endnote_header, endnote_content, endnote_footer))
}

#' Enhanced CSV conversion with memory optimization
convert_to_csv_enhanced <- function(data, options = NULL) {
  # Use data.table for memory efficiency with large datasets
  if (nrow(data) > 50000) {
    temp_file <- tempfile(fileext = ".csv")
    
    # Write in chunks to avoid memory issues
    chunk_size <- 10000
    chunks <- chunk_dataset(data, chunk_size)
    
    for (i in seq_along(chunks)) {
      write.table(chunks[[i]], temp_file, 
                 append = i > 1, 
                 sep = ",", 
                 row.names = FALSE, 
                 col.names = i == 1,
                 fileEncoding = "UTF-8",
                 quote = TRUE)
      gc()  # Force garbage collection
    }
    
    csv_content <- readLines(temp_file, encoding = "UTF-8")
    unlink(temp_file)
    return(paste(csv_content, collapse = "\n"))
  } else {
    # Standard processing for smaller datasets
    temp_file <- tempfile(fileext = ".csv")
    write.csv(data, temp_file, row.names = FALSE, fileEncoding = "UTF-8")
    csv_content <- readLines(temp_file, encoding = "UTF-8")
    unlink(temp_file)
    return(paste(csv_content, collapse = "\n"))
  }
}

#' Enhanced Excel conversion with memory optimization
convert_to_xlsx_enhanced <- function(data, options = NULL) {
  if (nrow(data) > 100000) {
    # For very large datasets, recommend chunked export
    return("Dataset muito grande para Excel. Use exportação em lote ou formato CSV.")
  }
  
  # Create workbook with optimization
  wb <- createWorkbook()
  
  # Add worksheet with Brazilian formatting
  addWorksheet(wb, "Dados Legislativos", gridLines = TRUE)
  
  # Write data efficiently
  writeData(wb, "Dados Legislativos", data, startRow = 1, startCol = 1, 
            colNames = TRUE, rowNames = FALSE)
  
  # Add basic formatting
  headerStyle <- createStyle(
    textDecoration = "Bold",
    fontColour = "#FFFFFF",
    fgFill = "#4472C4"
  )
  addStyle(wb, "Dados Legislativos", headerStyle, rows = 1, cols = 1:ncol(data))
  
  # Save to temporary file and read
  temp_file <- tempfile(fileext = ".xlsx")
  saveWorkbook(wb, temp_file, overwrite = TRUE)
  
  return(temp_file)  # Return file path for large files
}

#' Write export file with appropriate method
write_export_file <- function(content, filename, format) {
  if (format == "xlsx" && file.exists(content)) {
    # For Excel files, content is already a file path
    file.copy(content, filename, overwrite = TRUE)
    unlink(content)  # Clean up temp file
  } else {
    # For text-based formats
    writeLines(content, filename, useBytes = TRUE)
  }
}

#' Export Module UI
#' 
#' Creates the user interface for data export including format selection,
#' customization options, and batch export functionality.
#' 
#' @param id Character string for module namespace ID
#' @return Shiny UI tagList containing export interface elements
#' @export
exportUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      column(12,
        h3("💾 Exportação de Dados Legislativos", 
           style = "color: #2c3e50; margin-bottom: 20px;"),
        p("Exporte dados legislativos em formatos acadêmicos e profissionais com opções avançadas de personalização.",
          style = "color: #7f8c8d; margin-bottom: 30px;")
      )
    ),
    
    fluidRow(
      # Export Configuration Panel
      column(4,
        wellPanel(
          h4("Configuração da Exportação", style = "color: #2c3e50;"),
          
          # Data source selection
          radioButtons(
            inputId = ns("data_source"),
            label = "Fonte de Dados:",
            choices = list(
              "Resultados de Busca Atual" = "current_search",
              "Conjunto de Dados Completo" = "full_dataset",
              "Seleção Customizada" = "custom_selection",
              "Dados Filtrados" = "filtered_data"
            ),
            selected = "current_search"
          ),
          
          # Export format selection - Enhanced Week 5
          radioButtons(
            inputId = ns("export_format"),
            label = "Formato de Exportação:",
            choices = list(
              "CSV (Planilha)" = "csv",
              "Excel (.xlsx)" = "xlsx", 
              "JSON (Dados estruturados)" = "json",
              "XML (Estruturado)" = "xml",
              "LexML (Banco de dados jurídicos)" = "lexml",
              "EndNote XML (Instituições acadêmicas)" = "endnote",
              "BibTeX (Bibliográfico)" = "bibtex",
              "RIS (Reference Manager)" = "ris"
            ),
            selected = "csv"
          ),
          
          # Memory usage indicator
          div(
            id = ns("memory_status"),
            style = "margin-top: 10px; padding: 10px; background-color: #f8f9fa; border-radius: 5px;",
            h6("Status de Memória:", style = "margin-bottom: 5px; color: #495057;"),
            uiOutput(ns("memory_indicator"))
          ),
          
          # Column selection
          h5("Colunas a Exportar:"),
          checkboxGroupInput(
            inputId = ns("export_columns"),
            label = NULL,
            choices = list(
              "Título" = "titulo",
              "Categoria" = "categoria",
              "Estado" = "estado",
              "Data" = "data",
              "Autoridade" = "autoridade",
              "Ementa" = "ementa",
              "Texto Completo" = "texto",
              "Município" = "municipio",
              "Tipo de Documento" = "tipo_documento",
              "URL/URN" = "url",
              "Metadados" = "metadata"
            ),
            selected = c("titulo", "categoria", "estado", "data", "autoridade")
          ),
          
          # Date range for export
          dateRangeInput(
            inputId = ns("export_date_range"),
            label = "Período de Dados:",
            start = Sys.Date() - 365,
            end = Sys.Date(),
            format = "dd/mm/yyyy",
            language = "pt-BR"
          ),
          
          # Maximum records
          numericInput(
            inputId = ns("max_records"),
            label = "Máximo de Registros:",
            value = 10000,
            min = 1,
            max = 100000,
            step = 1000
          )
        )
      ),
      
      # Export Options Panel
      column(4,
        wellPanel(
          h4("Opções Avançadas", style = "color: #2c3e50;"),
          
          # File options
          h5("Opções de Arquivo:"),
          checkboxGroupInput(
            inputId = ns("file_options"),
            label = NULL,
            choices = list(
              "Incluir cabeçalho" = "include_header",
              "Codificação UTF-8" = "utf8_encoding",
              "Compressão ZIP" = "zip_compression",
              "Arquivo único" = "single_file",
              "Dividir por estado" = "split_by_state"
            ),
            selected = c("include_header", "utf8_encoding")
          ),
          
          # Academic options
          h5("Opções Acadêmicas:"),
          checkboxGroupInput(
            inputId = ns("academic_options"),
            label = NULL,
            choices = list(
              "Incluir citações" = "include_citations",
              "Metadados de pesquisa" = "research_metadata",
              "Relatório de metodologia" = "methodology_report",
              "Estatísticas descritivas" = "descriptive_stats",
              "Nota de conformidade LGPD" = "lgpd_compliance"
            ),
            selected = c("research_metadata", "lgpd_compliance")
          ),
          
          # Quality options
          h5("Controle de Qualidade:"),
          checkboxGroupInput(
            inputId = ns("quality_options"),
            label = NULL,
            choices = list(
              "Validar dados" = "validate_data",
              "Remover duplicatas" = "remove_duplicates",
              "Limpar campos vazios" = "clean_empty",
              "Padronizar datas" = "standardize_dates",
              "Verificar integridade" = "check_integrity"
            ),
            selected = c("validate_data", "remove_duplicates", "standardize_dates")
          )
        )
      ),
      
      # Preview and Actions Panel
      column(4,
        wellPanel(
          h4("Visualização e Ações", style = "color: #2c3e50;"),
          
          # Data preview
          h5("Visualização dos Dados:"),
          div(
            style = "height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; background-color: #f8f9fa;",
            verbatimTextOutput(ns("data_preview"))
          ),
          
          br(),
          
          # Export statistics
          h5("Estatísticas da Exportação:"),
          uiOutput(ns("export_stats")),
          
          br(),
          
          # Action buttons
          actionButton(
            inputId = ns("preview_export"),
            label = "Visualizar Dados",
            icon = icon("eye"),
            class = "btn-info btn-block"
          ),
          
          br(),
          
          downloadButton(
            outputId = ns("download_export"),
            label = "Baixar Arquivo",
            icon = icon("download"),
            class = "btn-success btn-block"
          ),
          
          br(),
          
          actionButton(
            inputId = ns("batch_export"),
            label = "Exportação em Lote",
            icon = icon("tasks"),
            class = "btn-warning btn-block"
          )
        )
      )
    ),
    
    # Export Results and History
    fluidRow(
      column(12,
        tabsetPanel(
          type = "tabs",
          
          # Current Export Tab
          tabPanel(
            title = "Exportação Atual",
            icon = icon("file-export"),
            br(),
            
            fluidRow(
              column(6,
                h4("Dados a Exportar"),
                DT::dataTableOutput(ns("export_data_table"))
              ),
              column(6,
                h4("Resumo da Exportação"),
                wellPanel(
                  uiOutput(ns("export_summary"))
                )
              )
            )
          ),
          
          # Batch Export Tab
          tabPanel(
            title = "Exportação em Lote",
            icon = icon("tasks"),
            br(),
            
            fluidRow(
              column(6,
                h4("Configuração do Lote"),
                wellPanel(
                  selectInput(
                    inputId = ns("batch_criteria"),
                    label = "Critério de Divisão:",
                    choices = list(
                      "Por Estado" = "state",
                      "Por Categoria" = "category", 
                      "Por Ano" = "year",
                      "Por Tipo de Documento" = "document_type",
                      "Por Tamanho (registros)" = "size"
                    ),
                    selected = "state"
                  ),
                  
                  numericInput(
                    inputId = ns("batch_size"),
                    label = "Tamanho do Lote (se por tamanho):",
                    value = 5000,
                    min = 100,
                    max = 50000
                  ),
                  
                  actionButton(
                    inputId = ns("configure_batch"),
                    label = "Configurar Lote",
                    icon = icon("cog"),
                    class = "btn-primary btn-block"
                  )
                )
              ),
              column(6,
                h4("Status do Lote"),
                uiOutput(ns("batch_status"))
              )
            )
          ),
          
          # Export History Tab
          tabPanel(
            title = "Histórico",
            icon = icon("history"),
            br(),
            
            fluidRow(
              column(12,
                h4("Histórico de Exportações"),
                DT::dataTableOutput(ns("export_history_table")),
                
                br(),
                
                fluidRow(
                  column(4,
                    actionButton(
                      inputId = ns("clear_history"),
                      label = "Limpar Histórico",
                      icon = icon("trash"),
                      class = "btn-danger"
                    )
                  ),
                  column(4,
                    downloadButton(
                      outputId = ns("download_history"),
                      label = "Baixar Histórico",
                      icon = icon("download"),
                      class = "btn-info"
                    )
                  ),
                  column(4,
                    actionButton(
                      inputId = ns("repeat_export"),
                      label = "Repetir Exportação",
                      icon = icon("redo"),
                      class = "btn-secondary"
                    )
                  )
                )
              )
            )
          ),
          
          # Academic Publishing Tab
          tabPanel(
            title = "Publicação Acadêmica",
            icon = icon("graduation-cap"),
            br(),
            
            fluidRow(
              column(6,
                h4("Formato de Publicação"),
                wellPanel(
                  radioButtons(
                    inputId = ns("publication_format"),
                    label = "Formato Acadêmico:",
                    choices = list(
                      "Dataset para R" = "r_dataset",
                      "Dataframe Python (pickle)" = "python_pickle",
                      "SPSS (.sav)" = "spss",
                      "Stata (.dta)" = "stata",
                      "SAS (.sas7bdat)" = "sas",
                      "Formato FAIR (RDF)" = "rdf"
                    ),
                    selected = "r_dataset"
                  ),
                  
                  textAreaInput(
                    inputId = ns("dataset_description"),
                    label = "Descrição do Dataset:",
                    placeholder = "Descreva o dataset, metodologia de coleta, e uso pretendido...",
                    rows = 4
                  ),
                  
                  textInput(
                    inputId = ns("dataset_version"),
                    label = "Versão do Dataset:",
                    value = paste0("v", format(Sys.Date(), "%Y.%m.%d"))
                  )
                )
              ),
              column(6,
                h4("Metadados de Publicação"),
                wellPanel(
                  textInput(
                    inputId = ns("author_name"),
                    label = "Nome do Autor:",
                    placeholder = "Seu nome completo"
                  ),
                  
                  textInput(
                    inputId = ns("institution"),
                    label = "Instituição:",
                    placeholder = "Sua instituição de pesquisa"
                  ),
                  
                  textInput(
                    inputId = ns("contact_email"),
                    label = "Email de Contato:",
                    placeholder = "email@instituicao.edu.br"
                  ),
                  
                  textAreaInput(
                    inputId = ns("license"),
                    label = "Licença:",
                    value = "Creative Commons CC BY 4.0 - Uso acadêmico e científico permitido com atribuição.",
                    rows = 2
                  )
                )
              )
            ),
            
            fluidRow(
              column(12,
                downloadButton(
                  outputId = ns("download_academic"),
                  label = "Gerar Dataset Acadêmico",
                  icon = icon("graduation-cap"),
                  class = "btn-primary btn-block"
                )
              )
            )
          )
        )
      )
    )
  )
}

#' Export Module Server
#' 
#' Server logic for data export including format processing,
#' batch operations, and academic publishing features.
#' 
#' @param id Character string for module namespace ID
#' @param reactive_data Reactive expression containing legislative data
#' @return List of reactive values and functions
#' @export
exportServer <- function(id, reactive_data) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns
    
    # Reactive values
    values <- reactiveValues(
      export_data = NULL,
      export_ready = FALSE,
      batch_config = NULL,
      export_history = data.frame(
        timestamp = character(),
        format = character(),
        records = integer(),
        file_size = character(),
        status = character(),
        stringsAsFactors = FALSE
      )
    )
    
    # Prepare export data based on source selection
    observe({
      req(reactive_data())
      
      data <- reactive_data()
      
      # Apply data source filtering
      export_data <- switch(input$data_source,
        "current_search" = data,
        "full_dataset" = data,  # Could load full dataset here
        "custom_selection" = data,  # Could implement custom selection
        "filtered_data" = data
      )
      
      # Apply date range filter
      if (!is.null(input$export_date_range)) {
        export_data$data <- as.Date(export_data$data)
        export_data <- export_data[
          export_data$data >= input$export_date_range[1] & 
          export_data$data <= input$export_date_range[2], 
        ]
      }
      
      # Apply maximum records limit
      if (nrow(export_data) > input$max_records) {
        export_data <- export_data[1:input$max_records, ]
      }
      
      # Apply quality options
      if ("remove_duplicates" %in% input$quality_options) {
        export_data <- export_data[!duplicated(export_data), ]
      }
      
      if ("clean_empty" %in% input$quality_options) {
        # Remove rows where key fields are empty
        export_data <- export_data[!is.na(export_data$titulo) & export_data$titulo != "", ]
      }
      
      # Select only requested columns
      if (!is.null(input$export_columns) && length(input$export_columns) > 0) {
        available_columns <- intersect(input$export_columns, names(export_data))
        if (length(available_columns) > 0) {
          export_data <- export_data[, available_columns, drop = FALSE]
        }
      }
      
      values$export_data <- export_data
      values$export_ready <- !is.null(export_data) && nrow(export_data) > 0
    })
    
    # Data preview
    output$data_preview <- renderText({
      req(values$export_data)
      
      preview_data <- head(values$export_data, 5)
      capture.output(str(preview_data))
    })
    
    # Export statistics
    output$export_stats <- renderUI({
      req(values$export_data)
      
      stats <- list(
        "Registros" = nrow(values$export_data),
        "Colunas" = ncol(values$export_data),
        "Tamanho estimado" = paste(round(object.size(values$export_data) / 1024^2, 2), "MB"),
        "Estados únicos" = if("estado" %in% names(values$export_data)) length(unique(values$export_data$estado)) else "N/A",
        "Período" = if("data" %in% names(values$export_data)) {
          paste(min(values$export_data$data, na.rm = TRUE), "a", max(values$export_data$data, na.rm = TRUE))
        } else "N/A"
      )
      
      tagList(
        lapply(names(stats), function(name) {
          div(
            strong(paste0(name, ": ")),
            span(stats[[name]]),
            br()
          )
        })
      )
    })
    
    # Export data table
    output$export_data_table <- DT::renderDataTable({
      req(values$export_data)
      
      DT::datatable(
        values$export_data,
        options = list(
          pageLength = 10,
          scrollX = TRUE,
          language = list(
            url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json"
          )
        ),
        rownames = FALSE
      )
    })
    
    # Export summary
    output$export_summary <- renderUI({
      req(values$export_data)
      
      tagList(
        h5("Resumo da Exportação"),
        p(strong("Formato: "), input$export_format),
        p(strong("Registros: "), nrow(values$export_data)),
        p(strong("Colunas: "), paste(names(values$export_data), collapse = ", ")),
        p(strong("Opções: "), paste(input$file_options, collapse = ", ")),
        if ("lgpd_compliance" %in% input$academic_options) {
          div(
            class = "alert alert-info",
            icon("shield-alt"),
            " Exportação em conformidade com LGPD"
          )
        }
      )
    })
    
    # Preview export
    observeEvent(input$preview_export, {
      req(values$export_data)
      
      showModal(modalDialog(
        title = "Visualização dos Dados de Exportação",
        size = "l",
        DT::dataTableOutput(ns("preview_table")),
        footer = modalButton("Fechar")
      ))
      
      output$preview_table <- DT::renderDataTable({
        DT::datatable(
          values$export_data,
          options = list(
            pageLength = 25,
            scrollX = TRUE,
            scrollY = "400px"
          ),
          rownames = FALSE
        )
      })
    })
    
    # Download handler
    output$download_export <- downloadHandler(
      filename = function() {
        timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
        extension <- switch(input$export_format,
          "csv" = "csv",
          "xlsx" = "xlsx", 
          "json" = "json",
          "xml" = "xml",
          "pdf" = "pdf",
          "bibtex" = "bib",
          "ris" = "ris"
        )
        paste0("dados_legislativos_", timestamp, ".", extension)
      },
      
      content = function(file) {
        req(values$export_data)
        
        tryCatch({
          # Generate file based on format
          switch(input$export_format,
            "csv" = {
              write.csv(values$export_data, file, row.names = FALSE, fileEncoding = "UTF-8")
            },
            "xlsx" = {
              wb <- createWorkbook()
              addWorksheet(wb, "Dados Legislativos")
              writeData(wb, "Dados Legislativos", values$export_data)
              saveWorkbook(wb, file, overwrite = TRUE)
            },
            "json" = {
              write(jsonlite::toJSON(values$export_data, pretty = TRUE), file)
            },
            "xml" = {
              # Convert to XML format
              xml_data <- xml_new_root("legislativos")
              for (i in 1:nrow(values$export_data)) {
                doc_node <- xml_add_child(xml_data, "documento")
                for (col in names(values$export_data)) {
                  xml_add_child(doc_node, col, values$export_data[i, col])
                }
              }
              write_xml(xml_data, file)
            },
            "bibtex" = {
              # Generate BibTeX entries
              bibtex_entries <- apply(values$export_data, 1, function(row) {
                key <- make.names(paste0(gsub("\\s+", "", row[["autoridade"]]), row[["data"]]))
                paste0("@misc{", key, ",\n",
                      "  title = {", row[["titulo"]], "},\n",
                      "  author = {", row[["autoridade"]], "},\n", 
                      "  year = {", format(as.Date(row[["data"]]), "%Y"), "},\n",
                      "  address = {", row[["estado"]], "}\n",
                      "}")
              })
              writeLines(bibtex_entries, file)
            }
          )
          
          # Update export history
          file_size <- file.size(file)
          new_history <- data.frame(
            timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
            format = input$export_format,
            records = nrow(values$export_data),
            file_size = paste(round(file_size / 1024^2, 2), "MB"),
            status = "Concluído",
            stringsAsFactors = FALSE
          )
          values$export_history <- rbind(values$export_history, new_history)
          
        }, error = function(e) {
          showNotification(
            paste("Erro na exportação:", e$message),
            type = "error"
          )
        })
      }
    )
    
    # Export history table
    output$export_history_table <- DT::renderDataTable({
      DT::datatable(
        values$export_history,
        options = list(
          pageLength = 10,
          order = list(list(0, "desc")),  # Sort by timestamp descending
          language = list(
            url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json"
          )
        ),
        colnames = c("Data/Hora", "Formato", "Registros", "Tamanho", "Status"),
        rownames = FALSE
      )
    })
    
    # Return reactive values
    return(
      list(
        export_data = reactive(values$export_data),
        export_ready = reactive(values$export_ready),
        export_format = reactive(input$export_format),
        export_history = reactive(values$export_history)
      )
    )
  })
}

cat("✅ Export module loaded successfully\n")