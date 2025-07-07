# Comprehensive Export System for Monitor Legislativo v4
# Enhanced export functionality with multiple formats and academic standards

library(openxlsx)
library(jsonlite)
library(knitr)
library(rmarkdown)
library(htmltools)
library(DT)
library(zip)

# Export configuration
EXPORT_CONFIG <- list(
  supported_formats = list(
    "csv" = "Comma Separated Values",
    "xlsx" = "Microsoft Excel Workbook",
    "json" = "JavaScript Object Notation",
    "html" = "HyperText Markup Language",
    "pdf" = "Portable Document Format",
    "xml" = "eXtensible Markup Language",
    "rds" = "R Data Serialization",
    "zip" = "Compressed Archive"
  ),
  
  export_templates = list(
    "academic_report" = "Relatório Acadêmico Completo",
    "data_summary" = "Resumo Executivo dos Dados",
    "statistical_analysis" = "Análise Estatística Detalhada",
    "geographic_analysis" = "Relatório de Análise Geográfica",
    "temporal_analysis" = "Análise Temporal Legislativa",
    "comparative_study" = "Estudo Comparativo",
    "research_dataset" = "Dataset para Pesquisa"
  ),
  
  quality_levels = list(
    "draft" = "Rascunho (Visualização)",
    "standard" = "Padrão (Publicação)",
    "publication" = "Publicação (Revisão por Pares)",
    "archive" = "Arquivo (Preservação a Longo Prazo)"
  ),
  
  compression_levels = c(1, 6, 9),  # zip compression levels
  
  max_file_size_mb = 100,
  max_records_export = 10000
)

#' Enhanced export function for legislative data
#' @param data Legislative documents data frame
#' @param format Export format
#' @param template Export template type
#' @param options Export options list
#' @param quality Quality level
#' @return File path to exported file or error message
export_legislative_data <- function(data, format = "csv", template = "research_dataset", 
                                  options = list(), quality = "standard") {
  
  if (is.null(data) || nrow(data) == 0) {
    log_event("No data provided for export", "ERROR")
    return(NULL)
  }
  
  log_event(paste("Starting export:", format, "template:", template, "quality:", quality))
  
  tryCatch({
    
    # Validate export parameters
    validation_result <- validate_export_parameters(data, format, template, options, quality)
    if (!validation_result$valid) {
      log_event(paste("Export validation failed:", validation_result$message), "ERROR")
      return(NULL)
    }
    
    # Apply data limits and filters
    processed_data <- prepare_data_for_export(data, options)
    
    # Generate export based on format and template
    export_result <- switch(format,
      "csv" = export_to_csv(processed_data, template, options, quality),
      "xlsx" = export_to_excel(processed_data, template, options, quality),
      "json" = export_to_json(processed_data, template, options, quality),
      "html" = export_to_html(processed_data, template, options, quality),
      "pdf" = export_to_pdf(processed_data, template, options, quality),
      "xml" = export_to_xml(processed_data, template, options, quality),
      "rds" = export_to_rds(processed_data, template, options, quality),
      "zip" = export_to_zip(processed_data, template, options, quality),
      NULL
    )
    
    if (!is.null(export_result)) {
      log_event(paste("Export completed successfully:", export_result))
      return(export_result)
    } else {
      log_event("Export failed - no result generated", "ERROR")
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("Error during export:", e$message), "ERROR")
    return(NULL)
  })
}

#' Validate export parameters
#' @param data Data frame
#' @param format Export format
#' @param template Template type
#' @param options Options list
#' @param quality Quality level
#' @return Validation result list
validate_export_parameters <- function(data, format, template, options, quality) {
  
  # Check data size
  if (nrow(data) > EXPORT_CONFIG$max_records_export) {
    return(list(
      valid = FALSE,
      message = paste("Dados excedem o limite de", EXPORT_CONFIG$max_records_export, "registros")
    ))
  }
  
  # Check format support
  if (!(format %in% names(EXPORT_CONFIG$supported_formats))) {
    return(list(
      valid = FALSE,
      message = paste("Formato não suportado:", format)
    ))
  }
  
  # Check template support
  if (!(template %in% names(EXPORT_CONFIG$export_templates))) {
    return(list(
      valid = FALSE,
      message = paste("Template não suportado:", template)
    ))
  }
  
  # Check quality level
  if (!(quality %in% names(EXPORT_CONFIG$quality_levels))) {
    return(list(
      valid = FALSE,
      message = paste("Nível de qualidade não suportado:", quality)
    ))
  }
  
  return(list(valid = TRUE, message = "Validation passed"))
}

#' Prepare data for export with filters and limits
#' @param data Original data
#' @param options Export options
#' @return Processed data
prepare_data_for_export <- function(data, options) {
  
  processed <- data
  
  # Apply record limit if specified
  if (!is.null(options$limit) && options$limit > 0) {
    processed <- head(processed, options$limit)
  }
  
  # Filter by date range if specified
  if (!is.null(options$date_from) && !is.null(options$date_to)) {
    processed <- processed %>%
      filter(
        as.Date(data) >= as.Date(options$date_from),
        as.Date(data) <= as.Date(options$date_to)
      )
  }
  
  # Filter by states if specified
  if (!is.null(options$states) && length(options$states) > 0) {
    processed <- processed %>%
      filter(estado %in% options$states)
  }
  
  # Filter by document types if specified
  if (!is.null(options$types) && length(options$types) > 0) {
    processed <- processed %>%
      filter(tipo %in% options$types)
  }
  
  # Add export metadata
  processed$export_timestamp <- Sys.time()
  processed$export_id <- paste0("ML4_", format(Sys.time(), "%Y%m%d_%H%M%S"))
  
  return(processed)
}

#' Export to CSV format
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_csv <- function(data, template, options, quality) {
  
  temp_file <- tempfile(fileext = ".csv")
  
  # Select columns based on template
  export_data <- select_columns_for_template(data, template)
  
  # Apply quality-specific formatting
  if (quality == "publication") {
    # Clean data for publication
    export_data <- clean_data_for_publication(export_data)
  }
  
  # Write CSV with appropriate encoding
  write.csv(
    export_data,
    temp_file,
    row.names = FALSE,
    fileEncoding = "UTF-8",
    na = ""
  )
  
  # Add metadata file if requested
  if (options$include_metadata) {
    metadata_file <- create_metadata_file(data, template, options, quality)
    # In a real implementation, would bundle files together
  }
  
  return(temp_file)
}

#' Export to Excel format
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_excel <- function(data, template, options, quality) {
  
  temp_file <- tempfile(fileext = ".xlsx")
  
  # Create workbook
  wb <- createWorkbook()
  
  # Main data sheet
  addWorksheet(wb, "Dados Legislativos")
  export_data <- select_columns_for_template(data, template)
  
  if (quality == "publication") {
    export_data <- clean_data_for_publication(export_data)
  }
  
  writeData(wb, "Dados Legislativos", export_data)
  
  # Summary sheet
  if (options$include_stats) {
    addWorksheet(wb, "Resumo Estatístico")
    summary_stats <- create_summary_statistics(data)
    writeData(wb, "Resumo Estatístico", summary_stats)
  }
  
  # Metadata sheet
  if (options$include_metadata) {
    addWorksheet(wb, "Metadados")
    metadata <- create_export_metadata(data, template, options, quality)
    writeData(wb, "Metadados", metadata)
  }
  
  # Charts sheet
  if (options$include_charts) {
    addWorksheet(wb, "Visualizações")
    # Add chart data (would need actual chart creation in full implementation)
    chart_data <- create_chart_data(data)
    writeData(wb, "Visualizações", chart_data)
  }
  
  # Citations sheet
  if (options$include_citations) {
    addWorksheet(wb, "Citações")
    citations <- create_export_citations(data)
    writeData(wb, "Citações", citations)
  }
  
  # Apply formatting based on quality level
  if (quality %in% c("publication", "archive")) {
    apply_excel_formatting(wb, quality)
  }
  
  saveWorkbook(wb, temp_file, overwrite = TRUE)
  
  return(temp_file)
}

#' Export to JSON format
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_json <- function(data, template, options, quality) {
  
  temp_file <- tempfile(fileext = ".json")
  
  # Prepare JSON structure
  export_structure <- list(
    metadata = create_export_metadata(data, template, options, quality),
    data = select_columns_for_template(data, template)
  )
  
  # Add optional components
  if (options$include_stats) {
    export_structure$statistics <- create_summary_statistics(data)
  }
  
  if (options$include_charts) {
    export_structure$visualizations <- create_chart_data(data)
  }
  
  if (options$include_citations) {
    export_structure$citations <- create_export_citations(data)
  }
  
  # Write JSON with appropriate settings
  json_settings <- list(
    pretty = quality %in% c("publication", "archive"),
    auto_unbox = TRUE,
    na = "null"
  )
  
  write_json(export_structure, temp_file, json_settings)
  
  return(temp_file)
}

#' Export to HTML report format
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_html <- function(data, template, options, quality) {
  
  temp_file <- tempfile(fileext = ".html")
  
  # Create HTML report based on template
  html_content <- switch(template,
    "academic_report" = create_academic_html_report(data, options, quality),
    "data_summary" = create_summary_html_report(data, options, quality),
    "statistical_analysis" = create_statistical_html_report(data, options, quality),
    "geographic_analysis" = create_geographic_html_report(data, options, quality),
    "temporal_analysis" = create_temporal_html_report(data, options, quality),
    "comparative_study" = create_comparative_html_report(data, options, quality),
    create_default_html_report(data, options, quality)
  )
  
  writeLines(html_content, temp_file)
  
  return(temp_file)
}

#' Export to PDF format
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_pdf <- function(data, template, options, quality) {
  
  # First create HTML then convert to PDF
  html_file <- export_to_html(data, template, options, quality)
  
  temp_file <- tempfile(fileext = ".pdf")
  
  # In a real implementation, would use tools like wkhtmltopdf or similar
  # For now, return the HTML file path
  # This would require additional PDF generation libraries
  
  log_event("PDF export requires additional configuration - returning HTML version")
  return(html_file)
}

#' Export to XML format
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_xml <- function(data, template, options, quality) {
  
  temp_file <- tempfile(fileext = ".xml")
  
  # Create XML structure
  xml_content <- create_xml_export(data, template, options, quality)
  
  writeLines(xml_content, temp_file)
  
  return(temp_file)
}

#' Export to R data format
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_rds <- function(data, template, options, quality) {
  
  temp_file <- tempfile(fileext = ".rds")
  
  # Prepare R data structure
  export_data <- list(
    data = select_columns_for_template(data, template),
    metadata = create_export_metadata(data, template, options, quality),
    export_info = list(
      template = template,
      quality = quality,
      options = options,
      exported_at = Sys.time(),
      r_version = R.version.string,
      monitor_legislativo_version = "4.0.0"
    )
  )
  
  # Add optional components
  if (options$include_stats) {
    export_data$statistics <- create_summary_statistics(data)
  }
  
  saveRDS(export_data, temp_file, compress = TRUE)
  
  return(temp_file)
}

#' Export to ZIP archive with multiple files
#' @param data Processed data
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return File path
export_to_zip <- function(data, template, options, quality) {
  
  temp_dir <- tempdir()
  zip_file <- tempfile(fileext = ".zip")
  
  # Create multiple export files
  files_to_zip <- character(0)
  
  # Main data file
  csv_file <- file.path(temp_dir, "dados_legislativos.csv")
  write.csv(select_columns_for_template(data, template), csv_file, row.names = FALSE, fileEncoding = "UTF-8")
  files_to_zip <- c(files_to_zip, csv_file)
  
  # Excel file
  excel_file <- file.path(temp_dir, "relatorio_completo.xlsx")
  wb <- createWorkbook()
  addWorksheet(wb, "Dados")
  writeData(wb, "Dados", select_columns_for_template(data, template))
  saveWorkbook(wb, excel_file, overwrite = TRUE)
  files_to_zip <- c(files_to_zip, excel_file)
  
  # JSON file
  json_file <- file.path(temp_dir, "dados_estruturados.json")
  write_json(list(data = data, metadata = create_export_metadata(data, template, options, quality)), json_file, pretty = TRUE)
  files_to_zip <- c(files_to_zip, json_file)
  
  # HTML report
  html_file <- file.path(temp_dir, "relatorio.html")
  writeLines(create_academic_html_report(data, options, quality), html_file)
  files_to_zip <- c(files_to_zip, html_file)
  
  # README file
  readme_file <- file.path(temp_dir, "README.txt")
  writeLines(create_readme_content(data, template, options, quality), readme_file)
  files_to_zip <- c(files_to_zip, readme_file)
  
  # Citations file
  if (options$include_citations) {
    citations_file <- file.path(temp_dir, "citacoes.txt")
    writeLines(create_export_citations(data), citations_file)
    files_to_zip <- c(files_to_zip, citations_file)
  }
  
  # Create ZIP archive
  zip::zip(zip_file, files = basename(files_to_zip), root = temp_dir)
  
  return(zip_file)
}

#' Select columns based on export template
#' @param data Original data
#' @param template Template type
#' @return Filtered data frame
select_columns_for_template <- function(data, template) {
  
  # Define column sets for each template
  column_sets <- list(
    "academic_report" = c("titulo", "tipo", "numero", "data", "autor", "estado", "ementa", "url", "fonte"),
    "data_summary" = c("titulo", "tipo", "data", "estado", "fonte"),
    "statistical_analysis" = c("titulo", "tipo", "numero", "data", "estado", "quality_score", "relevancia_transporte", "categoria"),
    "geographic_analysis" = c("titulo", "tipo", "data", "estado", "municipio", "regiao", "coordenadas"),
    "temporal_analysis" = c("titulo", "tipo", "numero", "data", "autor", "estado", "categoria"),
    "comparative_study" = c("titulo", "tipo", "numero", "data", "estado", "ementa", "categoria", "quality_score"),
    "research_dataset" = names(data)  # All columns
  )
  
  selected_columns <- column_sets[[template]] %||% names(data)
  
  # Filter to only existing columns
  existing_columns <- intersect(selected_columns, names(data))
  
  return(data[, existing_columns, drop = FALSE])
}

#' Clean data for publication quality
#' @param data Data frame
#' @return Cleaned data frame
clean_data_for_publication <- function(data) {
  
  cleaned <- data %>%
    # Remove incomplete records
    filter(!is.na(titulo), !is.na(tipo), !is.na(data)) %>%
    # Standardize text fields
    mutate(
      titulo = str_trim(titulo),
      tipo = str_to_title(tipo),
      autor = if ("autor" %in% names(.)) str_trim(autor) else NA,
      ementa = if ("ementa" %in% names(.)) str_trim(ementa) else NA
    ) %>%
    # Remove duplicates
    distinct(titulo, tipo, numero, data, .keep_all = TRUE)
  
  return(cleaned)
}

#' Create summary statistics
#' @param data Data frame
#' @return Summary statistics data frame
create_summary_statistics <- function(data) {
  
  stats <- data.frame(
    Métrica = character(),
    Valor = character(),
    stringsAsFactors = FALSE
  )
  
  # Basic counts
  stats <- rbind(stats, data.frame(
    Métrica = "Total de Documentos",
    Valor = format(nrow(data), big.mark = ".")
  ))
  
  # By type
  type_counts <- table(data$tipo)
  for (type in names(type_counts)) {
    stats <- rbind(stats, data.frame(
      Métrica = paste("Documentos -", type),
      Valor = format(type_counts[type], big.mark = ".")
    ))
  }
  
  # By state
  if ("estado" %in% names(data)) {
    state_count <- length(unique(data$estado[!is.na(data$estado)]))
    stats <- rbind(stats, data.frame(
      Métrica = "Estados Representados",
      Valor = as.character(state_count)
    ))
  }
  
  # Date range
  if ("data" %in% names(data)) {
    dates <- as.Date(data$data[!is.na(data$data)])
    if (length(dates) > 0) {
      stats <- rbind(stats, data.frame(
        Métrica = "Data Mais Antiga",
        Valor = format(min(dates), "%d/%m/%Y")
      ))
      stats <- rbind(stats, data.frame(
        Métrica = "Data Mais Recente",
        Valor = format(max(dates), "%d/%m/%Y")
      ))
    }
  }
  
  return(stats)
}

#' Create export metadata
#' @param data Data frame
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return Metadata data frame
create_export_metadata <- function(data, template, options, quality) {
  
  metadata <- data.frame(
    Campo = c(
      "Data de Exportação",
      "Template Utilizado",
      "Nível de Qualidade",
      "Total de Registros",
      "Formato de Dados",
      "Codificação",
      "Versão da Plataforma",
      "Fonte dos Dados"
    ),
    Valor = c(
      format(Sys.time(), "%d/%m/%Y %H:%M:%S"),
      EXPORT_CONFIG$export_templates[[template]],
      EXPORT_CONFIG$quality_levels[[quality]],
      nrow(data),
      class(data)[1],
      "UTF-8",
      "Monitor Legislativo v4.0.0",
      "LexML Brasil, APIs Governamentais"
    ),
    stringsAsFactors = FALSE
  )
  
  # Add optional metadata
  if (!is.null(options$date_from) && !is.null(options$date_to)) {
    metadata <- rbind(metadata, data.frame(
      Campo = "Período dos Dados",
      Valor = paste(options$date_from, "a", options$date_to)
    ))
  }
  
  if (!is.null(options$states) && length(options$states) > 0) {
    metadata <- rbind(metadata, data.frame(
      Campo = "Estados Filtrados",
      Valor = paste(options$states, collapse = ", ")
    ))
  }
  
  return(metadata)
}

#' Create chart data for export
#' @param data Data frame
#' @return Chart data structure
create_chart_data <- function(data) {
  
  chart_data <- list()
  
  # Document type distribution
  if ("tipo" %in% names(data)) {
    type_dist <- as.data.frame(table(data$tipo))
    names(type_dist) <- c("Tipo", "Quantidade")
    chart_data$distribuicao_tipos <- type_dist
  }
  
  # Temporal distribution
  if ("data" %in% names(data)) {
    dates <- as.Date(data$data[!is.na(data$data)])
    if (length(dates) > 0) {
      years <- format(dates, "%Y")
      year_dist <- as.data.frame(table(years))
      names(year_dist) <- c("Ano", "Quantidade")
      chart_data$distribuicao_temporal <- year_dist
    }
  }
  
  # Geographic distribution
  if ("estado" %in% names(data)) {
    state_dist <- as.data.frame(table(data$estado))
    names(state_dist) <- c("Estado", "Quantidade")
    chart_data$distribuicao_geografica <- state_dist
  }
  
  return(chart_data)
}

#' Create export citations
#' @param data Data frame
#' @return Character vector of citations
create_export_citations <- function(data) {
  
  citations <- c(
    "CITAÇÃO DA PLATAFORMA:",
    "",
    paste0("Monitor Legislativo v4. Dados legislativos brasileiros. ",
           "Consultado em ", format(Sys.Date(), "%d de %B de %Y"), ". ",
           "Plataforma acadêmica de pesquisa legislativa."),
    "",
    "FONTES DE DADOS:",
    "",
    "- LexML Brasil (Rede de Informação Legislativa e Jurídica)",
    "- Câmara dos Deputados do Brasil",
    "- Senado Federal do Brasil", 
    "- Assembleias Legislativas Estaduais",
    "- IBGE (Instituto Brasileiro de Geografia e Estatística)",
    "",
    "METODOLOGIA:",
    "",
    "Os dados foram coletados através de APIs governamentais oficiais,",
    "processados com algoritmos de validação e qualidade, e organizados",
    "seguindo padrões de metadados internacionais para preservação digital.",
    "",
    paste("Total de documentos exportados:", nrow(data)),
    paste("Data de exportação:", format(Sys.time(), "%d/%m/%Y %H:%M:%S"))
  )
  
  return(citations)
}

#' Create academic HTML report
#' @param data Data frame
#' @param options Export options
#' @param quality Quality level
#' @return HTML content string
create_academic_html_report <- function(data, options, quality) {
  
  # Get summary statistics
  stats <- create_summary_statistics(data)
  metadata <- create_export_metadata(data, "academic_report", options, quality)
  
  html_content <- paste0(
    "<!DOCTYPE html>",
    "<html lang='pt-BR'>",
    "<head>",
    "<meta charset='UTF-8'>",
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
    "<title>Relatório Acadêmico - Monitor Legislativo v4</title>",
    "<style>",
    "body { font-family: 'Times New Roman', serif; max-width: 1000px; margin: 0 auto; padding: 20px; line-height: 1.6; }",
    ".header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }",
    ".section { margin: 20px 0; }",
    ".stats-table { width: 100%; border-collapse: collapse; margin: 20px 0; }",
    ".stats-table th, .stats-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
    ".stats-table th { background-color: #f2f2f2; }",
    ".data-table { width: 100%; border-collapse: collapse; font-size: 0.9em; }",
    ".data-table th, .data-table td { border: 1px solid #ddd; padding: 6px; }",
    ".footer { margin-top: 50px; padding-top: 20px; border-top: 1px solid #ccc; font-size: 0.9em; color: #666; }",
    "</style>",
    "</head>",
    "<body>",
    
    # Header
    "<div class='header'>",
    "<h1>Relatório Acadêmico</h1>",
    "<h2>Análise de Dados Legislativos Brasileiros</h2>",
    "<p><strong>Monitor Legislativo v4</strong></p>",
    "<p>Gerado em: ", format(Sys.time(), "%d de %B de %Y às %H:%M"), "</p>",
    "</div>",
    
    # Executive Summary
    "<div class='section'>",
    "<h2>1. Resumo Executivo</h2>",
    "<p>Este relatório apresenta uma análise compreensiva de ", nrow(data), " documentos ",
    "legislativos brasileiros coletados através da plataforma Monitor Legislativo v4. ",
    "Os dados abrangem diferentes tipos de documentos legislativos de várias jurisdições ",
    "e períodos temporais, fornecendo uma visão abrangente do panorama legislativo nacional.</p>",
    "</div>",
    
    # Statistics Section
    "<div class='section'>",
    "<h2>2. Estatísticas Descritivas</h2>",
    "<table class='stats-table'>",
    "<thead><tr><th>Métrica</th><th>Valor</th></tr></thead>",
    "<tbody>",
    paste0(apply(stats, 1, function(row) {
      paste0("<tr><td>", row[1], "</td><td>", row[2], "</td></tr>")
    }), collapse = ""),
    "</tbody>",
    "</table>",
    "</div>",
    
    # Data Sample
    if (nrow(data) > 0) {
      sample_data <- head(data, 10)
      paste0(
        "<div class='section'>",
        "<h2>3. Amostra dos Dados</h2>",
        "<p>As primeiras 10 entradas do conjunto de dados:</p>",
        "<table class='data-table'>",
        "<thead><tr>",
        paste0("<th>", names(sample_data), "</th>", collapse = ""),
        "</tr></thead>",
        "<tbody>",
        paste0(apply(sample_data, 1, function(row) {
          paste0("<tr>", paste0("<td>", htmlEscape(as.character(row)), "</td>", collapse = ""), "</tr>")
        }), collapse = ""),
        "</tbody>",
        "</table>",
        "</div>"
      )
    } else "",
    
    # Methodology
    "<div class='section'>",
    "<h2>4. Metodologia</h2>",
    "<p>Os dados foram coletados através de APIs governamentais oficiais, incluindo:",
    "<ul>",
    "<li>LexML Brasil - Rede de Informação Legislativa e Jurídica</li>",
    "<li>APIs das Casas Legislativas (Câmara e Senado)</li>",
    "<li>Sistemas das Assembleias Legislativas Estaduais</li>",
    "<li>IBGE para dados geográficos e demográficos</li>",
    "</ul>",
    "Todos os dados passaram por processo de validação, limpeza e enriquecimento ",
    "antes da análise.</p>",
    "</div>",
    
    # Metadata Section
    "<div class='section'>",
    "<h2>5. Metadados da Exportação</h2>",
    "<table class='stats-table'>",
    "<thead><tr><th>Campo</th><th>Valor</th></tr></thead>",
    "<tbody>",
    paste0(apply(metadata, 1, function(row) {
      paste0("<tr><td>", row[1], "</td><td>", row[2], "</td></tr>")
    }), collapse = ""),
    "</tbody>",
    "</table>",
    "</div>",
    
    # Footer
    "<div class='footer'>",
    "<p><strong>Monitor Legislativo v4</strong> - Plataforma Acadêmica de Pesquisa Legislativa</p>",
    "<p>Desenvolvido para análise e pesquisa de dados legislativos brasileiros</p>",
    "<p>Para mais informações sobre metodologia e fontes, consulte a documentação técnica.</p>",
    "</div>",
    
    "</body>",
    "</html>"
  )
  
  return(html_content)
}

#' Create README content for ZIP exports
#' @param data Data frame
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return README content
create_readme_content <- function(data, template, options, quality) {
  
  readme <- c(
    "MONITOR LEGISLATIVO V4 - PACOTE DE EXPORTAÇÃO",
    "=" %>% rep(50) %>% paste(collapse = ""),
    "",
    "Este arquivo contém dados legislativos brasileiros exportados da plataforma",
    "Monitor Legislativo v4, uma ferramenta acadêmica para análise de documentos",
    "legislativos nacionais.",
    "",
    "CONTEÚDO DO PACOTE:",
    "- dados_legislativos.csv: Dados principais em formato tabular",
    "- relatorio_completo.xlsx: Planilha Excel com múltiplas abas",
    "- dados_estruturados.json: Dados em formato JSON",
    "- relatorio.html: Relatório acadêmico em HTML",
    "- citacoes.txt: Informações de citação acadêmica (se incluído)",
    "- README.txt: Este arquivo",
    "",
    "INFORMAÇÕES DA EXPORTAÇÃO:",
    paste("- Template utilizado:", EXPORT_CONFIG$export_templates[[template]]),
    paste("- Nível de qualidade:", EXPORT_CONFIG$quality_levels[[quality]]),
    paste("- Total de registros:", nrow(data)),
    paste("- Data de exportação:", format(Sys.time(), "%d/%m/%Y %H:%M:%S")),
    "",
    "FORMATO DOS DADOS:",
    "Os dados estão organizados com as seguintes colunas principais:",
    "- titulo: Título do documento legislativo",
    "- tipo: Tipo de documento (Lei, Decreto, etc.)",
    "- numero: Número do documento",
    "- data: Data de publicação",
    "- estado: Estado de origem",
    "- autor: Autor/Proponente (quando disponível)",
    "- ementa: Ementa/Resumo do documento",
    "",
    "FONTES DE DADOS:",
    "- LexML Brasil",
    "- Câmara dos Deputados",
    "- Senado Federal",
    "- Assembleias Legislativas",
    "- IBGE (dados geográficos)",
    "",
    "CITAÇÃO ACADÊMICA:",
    paste0("Monitor Legislativo v4. Dados legislativos brasileiros. ",
           "Consultado em ", format(Sys.Date(), "%d de %B de %Y"), ". ",
           "Plataforma acadêmica de pesquisa."),
    "",
    "CONTATO:",
    "Para dúvidas sobre os dados ou metodologia, consulte a documentação",
    "técnica da plataforma Monitor Legislativo v4.",
    "",
    "=" %>% rep(50) %>% paste(collapse = "")
  )
  
  return(readme)
}

#' Create XML export structure
#' @param data Data frame
#' @param template Template type
#' @param options Export options
#' @param quality Quality level
#' @return XML content string
create_xml_export <- function(data, template, options, quality) {
  
  xml_header <- paste0(
    '<?xml version="1.0" encoding="UTF-8"?>',
    '\n<monitor_legislativo version="4.0">',
    '\n  <metadata>',
    '\n    <export_date>', Sys.time(), '</export_date>',
    '\n    <template>', template, '</template>',
    '\n    <quality>', quality, '</quality>',
    '\n    <total_records>', nrow(data), '</total_records>',
    '\n  </metadata>',
    '\n  <documents>'
  )
  
  xml_body <- ""
  for (i in 1:min(nrow(data), 1000)) {  # Limit for XML size
    doc <- data[i, ]
    xml_body <- paste0(xml_body,
      '\n    <document id="', i, '">',
      '\n      <titulo><![CDATA[', doc$titulo %||% '', ']]></titulo>',
      '\n      <tipo>', doc$tipo %||% '', '</tipo>',
      '\n      <numero>', doc$numero %||% '', '</numero>',
      '\n      <data>', doc$data %||% '', '</data>',
      '\n      <estado>', doc$estado %||% '', '</estado>',
      '\n      <autor><![CDATA[', doc$autor %||% '', ']]></autor>',
      '\n      <ementa><![CDATA[', doc$ementa %||% '', ']]></ementa>',
      '\n    </document>'
    )
  }
  
  xml_footer <- paste0(
    '\n  </documents>',
    '\n</monitor_legislativo>'
  )
  
  return(paste0(xml_header, xml_body, xml_footer))
}

#' Apply Excel formatting based on quality level
#' @param wb Workbook object
#' @param quality Quality level
apply_excel_formatting <- function(wb, quality) {
  
  if (quality == "publication") {
    # Apply publication-quality formatting
    header_style <- createStyle(
      fontSize = 12,
      fontName = "Times New Roman",
      textDecoration = "bold",
      fgFill = "#E6E6FA",
      border = "TopBottomLeftRight"
    )
    
    addStyle(wb, "Dados Legislativos", header_style, rows = 1, cols = 1:20, gridExpand = TRUE)
  }
  
  if (quality == "archive") {
    # Apply archival formatting with metadata
    # Add additional metadata sheets and formatting for long-term preservation
  }
}

#' Helper function for HTML escaping
htmlEscape <- function(text) {
  if (is.na(text)) return("")
  text <- gsub("&", "&amp;", text)
  text <- gsub("<", "&lt;", text)
  text <- gsub(">", "&gt;", text)
  text <- gsub('"', "&quot;", text)
  return(text)
}

#' Helper function for null coalescing
`%||%` <- function(x, y) {
  if (is.null(x) || length(x) == 0 || all(is.na(x))) y else x
}