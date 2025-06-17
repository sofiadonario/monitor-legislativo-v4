# Export Utilities for Academic Legislative Data
# Exports real Brazilian legislative data in academic formats

library(openxlsx)
library(xml2)
library(htmltools)
library(knitr)
library(rmarkdown)
library(futile.logger)

#' Export legislative data to CSV format
#' @param data Legislative data frame
#' @param filename Output filename (optional)
#' @param include_metadata Whether to include metadata columns
#' @return File path of exported file
export_to_csv <- function(data, filename = NULL, include_metadata = TRUE) {
  
  if (is.null(data) || nrow(data) == 0) {
    flog.error("No data to export")
    return(NULL)
  }
  
  if (is.null(filename)) {
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("dados_legislativos_", timestamp, ".csv")
  }
  
  flog.info("Exporting %d records to CSV: %s", nrow(data), filename)
  
  # Prepare export data
  export_data <- data %>%
    select(
      ID = id_unico,
      Titulo = titulo,
      Tipo = tipo,
      Numero = numero,
      Data = data,
      Ano = ano,
      Resumo = resumo,
      Autor = autor,
      Status = status,
      Estado = estado,
      Municipio = municipio,
      Nivel = nivel_governo,
      URL = url,
      if (include_metadata) Fonte else NULL,
      if (include_metadata) Citacao = citacao else NULL,
      if (include_metadata) Palavras_Chave = palavras_chave else NULL,
      if (include_metadata) Data_Coleta = data_processamento else NULL
    ) %>%
    # Clean data for CSV export
    mutate(
      across(where(is.character), ~replace_na(.x, "")),
      across(where(is.Date), ~format(.x, "%Y-%m-%d")),
      across(where(is.POSIXct), ~format(.x, "%Y-%m-%d %H:%M:%S"))
    )
  
  tryCatch({
    # Write CSV with UTF-8 encoding
    write.csv(export_data, filename, fileEncoding = "UTF-8", row.names = FALSE, na = "")
    
    flog.info("CSV export completed: %s", filename)
    return(filename)
    
  }, error = function(e) {
    flog.error("Error exporting CSV: %s", e$message)
    return(NULL)
  })
}

#' Export legislative data to Excel format
#' @param data Legislative data frame
#' @param filename Output filename (optional)
#' @param include_summary Whether to include summary sheet
#' @return File path of exported file
export_to_excel <- function(data, filename = NULL, include_summary = TRUE) {
  
  if (is.null(data) || nrow(data) == 0) {
    flog.error("No data to export")
    return(NULL)
  }
  
  if (is.null(filename)) {
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("dados_legislativos_", timestamp, ".xlsx")
  }
  
  flog.info("Exporting %d records to Excel: %s", nrow(data), filename)
  
  tryCatch({
    # Create workbook
    wb <- createWorkbook()
    
    # Main data sheet
    addWorksheet(wb, "Dados Legislativos")
    
    # Prepare main data
    export_data <- data %>%
      select(
        ID = id_unico,
        Titulo = titulo,
        Tipo = tipo,
        Numero = numero,
        Data = data,
        Ano = ano,
        Resumo = resumo,
        Autor = autor,
        Status = status,
        Estado = estado,
        Municipio = municipio,
        Nivel = nivel_governo,
        Fonte = fonte_original,
        URL = url,
        Citacao = citacao,
        Palavras_Chave = palavras_chave
      ) %>%
      mutate(
        across(where(is.character), ~replace_na(.x, "")),
        across(where(is.Date), ~format(.x, "%Y-%m-%d"))
      )
    
    # Write main data
    writeData(wb, "Dados Legislativos", export_data)
    
    # Add summary sheet
    if (include_summary) {
      addWorksheet(wb, "Resumo")
      
      summary_data <- create_summary_statistics(data)
      writeData(wb, "Resumo", summary_data)
    }
    
    # Add metadata sheet
    addWorksheet(wb, "Metadados")
    metadata <- create_export_metadata(data)
    writeData(wb, "Metadados", metadata)
    
    # Save workbook
    saveWorkbook(wb, filename, overwrite = TRUE)
    
    flog.info("Excel export completed: %s", filename)
    return(filename)
    
  }, error = function(e) {
    flog.error("Error exporting Excel: %s", e$message)
    return(NULL)
  })
}

#' Export legislative data to XML format
#' @param data Legislative data frame
#' @param filename Output filename (optional)
#' @param include_metadata Whether to include metadata
#' @return File path of exported file
export_to_xml <- function(data, filename = NULL, include_metadata = TRUE) {
  
  if (is.null(data) || nrow(data) == 0) {
    flog.error("No data to export")
    return(NULL)
  }
  
  if (is.null(filename)) {
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("dados_legislativos_", timestamp, ".xml")
  }
  
  flog.info("Exporting %d records to XML: %s", nrow(data), filename)
  
  tryCatch({
    # Create root XML document
    doc <- xml_new_root("dados_legislativos")
    
    # Add metadata
    if (include_metadata) {
      metadata_node <- xml_add_child(doc, "metadados")
      xml_add_child(metadata_node, "data_exportacao", format(Sys.time(), "%Y-%m-%d %H:%M:%S"))
      xml_add_child(metadata_node, "total_documentos", nrow(data))
      xml_add_child(metadata_node, "fonte", "Monitor Legislativo Acadêmico")
      xml_add_child(metadata_node, "versao", "1.0")
      
      # Add summary statistics
      summary_stats <- create_summary_statistics(data)
      stats_node <- xml_add_child(metadata_node, "estatisticas")
      for (i in 1:nrow(summary_stats)) {
        stat_node <- xml_add_child(stats_node, "estatistica")
        xml_add_child(stat_node, "categoria", summary_stats$Categoria[i])
        xml_add_child(stat_node, "valor", summary_stats$Valor[i])
      }
    }
    
    # Add documents
    docs_node <- xml_add_child(doc, "documentos")
    
    for (i in 1:nrow(data)) {
      doc_node <- xml_add_child(docs_node, "documento")
      
      # Add document fields
      xml_add_child(doc_node, "id", data$id_unico[i] %||% "")
      xml_add_child(doc_node, "titulo", data$titulo[i] %||% "")
      xml_add_child(doc_node, "tipo", data$tipo[i] %||% "")
      xml_add_child(doc_node, "numero", data$numero[i] %||% "")
      xml_add_child(doc_node, "data", format(as.Date(data$data[i]), "%Y-%m-%d"))
      xml_add_child(doc_node, "ano", data$ano[i] %||% "")
      xml_add_child(doc_node, "resumo", data$resumo[i] %||% "")
      xml_add_child(doc_node, "autor", data$autor[i] %||% "")
      xml_add_child(doc_node, "status", data$status[i] %||% "")
      
      # Geographic information
      geo_node <- xml_add_child(doc_node, "localizacao")
      xml_add_child(geo_node, "estado", data$estado[i] %||% "")
      xml_add_child(geo_node, "municipio", data$municipio[i] %||% "")
      xml_add_child(geo_node, "nivel", data$nivel_governo[i] %||% "")
      
      # Metadata
      meta_node <- xml_add_child(doc_node, "metadados_documento")
      xml_add_child(meta_node, "fonte", data$fonte_original[i] %||% "")
      xml_add_child(meta_node, "url", data$url[i] %||% "")
      xml_add_child(meta_node, "citacao", data$citacao[i] %||% "")
      xml_add_child(meta_node, "palavras_chave", data$palavras_chave[i] %||% "")
    }
    
    # Write XML file
    write_xml(doc, filename, options = c("format", "no_declaration"))
    
    flog.info("XML export completed: %s", filename)
    return(filename)
    
  }, error = function(e) {
    flog.error("Error exporting XML: %s", e$message)
    return(NULL)
  })
}

#' Export legislative data to HTML report
#' @param data Legislative data frame
#' @param filename Output filename (optional)
#' @param include_maps Whether to include map visualizations
#' @return File path of exported file
export_to_html <- function(data, filename = NULL, include_maps = FALSE) {
  
  if (is.null(data) || nrow(data) == 0) {
    flog.error("No data to export")
    return(NULL)
  }
  
  if (is.null(filename)) {
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("relatorio_legislativo_", timestamp, ".html")
  }
  
  flog.info("Exporting %d records to HTML report: %s", nrow(data), filename)
  
  tryCatch({
    # Create HTML document
    html_content <- create_html_report(data, include_maps)
    
    # Write to file
    writeLines(html_content, filename, useBytes = TRUE)
    
    flog.info("HTML export completed: %s", filename)
    return(filename)
    
  }, error = function(e) {
    flog.error("Error exporting HTML: %s", e$message)
    return(NULL)
  })
}

#' Create comprehensive HTML report
#' @param data Legislative data frame
#' @param include_maps Whether to include map visualizations
#' @return HTML string
create_html_report <- function(data, include_maps = FALSE) {
  
  # Summary statistics
  summary_stats <- create_summary_statistics(data)
  
  # Geographic distribution
  geo_stats <- data %>%
    filter(!is.na(estado)) %>%
    count(estado, sort = TRUE) %>%
    slice_head(n = 10)
  
  # Document types
  type_stats <- data %>%
    count(tipo, sort = TRUE)
  
  # Recent documents
  recent_docs <- data %>%
    arrange(desc(data)) %>%
    slice_head(n = 20)
  
  # Create HTML
  html_content <- paste0(
    '<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório Legislativo - Monitor Acadêmico</title>
    <style>
        body {
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007bff;
            margin: 0;
            font-size: 2.5em;
        }
        .summary {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border-left: 5px solid #007bff;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #28a745;
        }
        .document {
            border: 1px solid #dee2e6;
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 5px;
            background: #fafafa;
        }
        .document h4 {
            color: #007bff;
            margin-top: 0;
        }
        .doc-meta {
            background: #fff;
            padding: 10px;
            border-left: 4px solid #17a2b8;
            margin: 10px 0;
            font-size: 0.9em;
        }
        .citation {
            background: #fff3cd;
            padding: 10px;
            border-left: 4px solid #ffc107;
            margin-top: 10px;
            font-style: italic;
            font-size: 0.9em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #dee2e6;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Relatório Legislativo</h1>
            <h2>Monitor Acadêmico - Brasil</h2>
            <p><strong>Gerado em:</strong> ', format(Sys.time(), "%d de %B de %Y às %H:%M"), '</p>
        </div>
        
        <div class="summary">
            <h2>📋 Resumo Executivo</h2>
            <p>Este relatório apresenta uma análise abrangente de <strong>', nrow(data), '</strong> documentos legislativos brasileiros coletados de fontes oficiais do governo federal, estadual e municipal.</p>
            <p><strong>Período analisado:</strong> ', min(as.Date(data$data), na.rm = TRUE), ' a ', max(as.Date(data$data), na.rm = TRUE), '</p>
            <p><strong>Fontes:</strong> ', length(unique(data$fonte_original)), ' diferentes APIs governamentais</p>
        </div>
        
        <div class="stats-grid">
            ', paste(apply(summary_stats, 1, function(row) {
                paste0('<div class="stat-card">
                    <div class="stat-number">', row["Valor"], '</div>
                    <div>', row["Categoria"], '</div>
                </div>')
            }), collapse = ""), '
        </div>
        
        <section>
            <h2>🗺️ Distribuição Geográfica</h2>
            <table>
                <thead>
                    <tr><th>Estado</th><th>Número de Documentos</th><th>Porcentagem</th></tr>
                </thead>
                <tbody>
                    ', paste(apply(geo_stats, 1, function(row) {
                        pct <- round(as.numeric(row["n"]) / nrow(data) * 100, 1)
                        paste0('<tr><td>', row["estado"], '</td><td>', row["n"], '</td><td>', pct, '%</td></tr>')
                    }), collapse = ""), '
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>📄 Tipos de Documento</h2>
            <table>
                <thead>
                    <tr><th>Tipo</th><th>Quantidade</th><th>Porcentagem</th></tr>
                </thead>
                <tbody>
                    ', paste(apply(type_stats, 1, function(row) {
                        pct <- round(as.numeric(row["n"]) / nrow(data) * 100, 1)
                        paste0('<tr><td>', str_to_title(row["tipo"]), '</td><td>', row["n"], '</td><td>', pct, '%</td></tr>')
                    }), collapse = ""), '
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>🆕 Documentos Mais Recentes</h2>
            ', paste(apply(recent_docs[1:min(10, nrow(recent_docs)), ], 1, function(row) {
                paste0('<div class="document">
                    <h4>', row["titulo"], '</h4>
                    <div class="doc-meta">
                        <strong>Tipo:</strong> ', str_to_title(row["tipo"]), ' | 
                        <strong>Número:</strong> ', row["numero"] %||% "S/N", ' | 
                        <strong>Data:</strong> ', format(as.Date(row["data"]), "%d/%m/%Y"), ' | 
                        <strong>Estado:</strong> ', row["estado"] %||% "Federal", '
                    </div>
                    <p>', str_trunc(row["resumo"], 300), '</p>
                    <div class="citation">
                        <strong>Citação:</strong> ', row["citacao"], '
                    </div>
                </div>')
            }), collapse = ""), '
        </section>
        
        <div class="footer">
            <h3>📖 Como Citar Este Relatório</h3>
            <p><strong>Citação sugerida:</strong></p>
            <p>Monitor Legislativo Acadêmico. Relatório de dados legislativos do Brasil. Gerado em ', format(Sys.Date(), "%d de %B de %Y"), '. Dados obtidos de APIs oficiais do governo brasileiro.</p>
            <hr>
            <p><em>Este relatório foi gerado automaticamente a partir de dados oficiais. Sempre verifique as fontes originais para uso acadêmico.</em></p>
            <p><strong>Fontes de dados:</strong> Câmara dos Deputados, Senado Federal, LexML Brasil, Assembleias Legislativas Estaduais</p>
        </div>
    </div>
</body>
</html>'
  )
  
  return(html_content)
}

#' Create summary statistics table
#' @param data Legislative data frame
#' @return Data frame with summary statistics
create_summary_statistics <- function(data) {
  
  summary_stats <- data.frame(
    Categoria = c(
      "Total de Documentos",
      "Estados com Legislação", 
      "Municípios com Legislação",
      "Documentos Federais",
      "Documentos Estaduais", 
      "Documentos Municipais",
      "Tipos de Documento",
      "Período (anos)",
      "Documento Mais Recente",
      "Fonte de Dados"
    ),
    Valor = c(
      nrow(data),
      length(unique(data$estado[!is.na(data$estado)])),
      length(unique(data$municipio[!is.na(data$municipio)])),
      sum(data$nivel_governo == "Federal", na.rm = TRUE),
      sum(data$nivel_governo == "Estadual", na.rm = TRUE),
      sum(data$nivel_governo == "Municipal", na.rm = TRUE),
      length(unique(data$tipo)),
      paste(min(year(as.Date(data$data)), na.rm = TRUE), "-", max(year(as.Date(data$data)), na.rm = TRUE)),
      format(max(as.Date(data$data), na.rm = TRUE), "%d/%m/%Y"),
      length(unique(data$fonte_original))
    ),
    stringsAsFactors = FALSE
  )
  
  return(summary_stats)
}

#' Create export metadata
#' @param data Legislative data frame
#' @return Data frame with metadata information
create_export_metadata <- function(data) {
  
  metadata <- data.frame(
    Campo = c(
      "Data da Exportação",
      "Versão do Sistema", 
      "Total de Registros",
      "APIs Consultadas",
      "Período dos Dados",
      "Observações"
    ),
    Valor = c(
      format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
      "1.0",
      nrow(data),
      paste(unique(data$fonte_original), collapse = ", "),
      paste(min(as.Date(data$data), na.rm = TRUE), "a", max(as.Date(data$data), na.rm = TRUE)),
      "Dados obtidos de APIs oficiais do governo brasileiro"
    ),
    stringsAsFactors = FALSE
  )
  
  return(metadata)
}

#' Generate academic report in PDF format (requires LaTeX)
#' @param data Legislative data frame
#' @param filename Output filename (optional)
#' @return File path of exported file
export_to_pdf <- function(data, filename = NULL) {
  
  if (is.null(filename)) {
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("relatorio_legislativo_", timestamp, ".pdf")
  }
  
  flog.info("Exporting academic PDF report: %s", filename)
  
  tryCatch({
    # Create temporary Rmd file
    rmd_content <- create_rmarkdown_report(data)
    temp_rmd <- tempfile(fileext = ".Rmd")
    writeLines(rmd_content, temp_rmd)
    
    # Render to PDF
    rmarkdown::render(
      input = temp_rmd,
      output_format = "pdf_document",
      output_file = filename,
      quiet = TRUE
    )
    
    # Clean up
    file.remove(temp_rmd)
    
    flog.info("PDF export completed: %s", filename)
    return(filename)
    
  }, error = function(e) {
    flog.error("Error exporting PDF (LaTeX may not be installed): %s", e$message)
    return(NULL)
  })
}

#' Create R Markdown content for academic report
#' @param data Legislative data frame
#' @return R Markdown content as string
create_rmarkdown_report <- function(data) {
  
  rmd_content <- '---
title: "Relatório Acadêmico de Dados Legislativos Brasileiros"
subtitle: "Monitor Legislativo Acadêmico"
author: "Sistema Automatizado"
date: "`r format(Sys.Date(), \"%d de %B de %Y\")`"
output:
  pdf_document:
    latex_engine: xelatex
    toc: true
    number_sections: true
header-includes:
  - \\usepackage{float}
  - \\usepackage{booktabs}
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(echo = FALSE, warning = FALSE, message = FALSE)
library(knitr)
library(dplyr)
library(ggplot2)
```

# Resumo Executivo

Este relatório apresenta uma análise de **`r nrow(data)`** documentos legislativos brasileiros coletados de fontes oficiais governamentais.

## Metodologia

Os dados foram coletados através de APIs oficiais do governo brasileiro, incluindo:
- Câmara dos Deputados
- Senado Federal  
- LexML Brasil
- Assembleias Legislativas Estaduais

# Análise dos Dados

## Distribuição Temporal

```{r temporal-analysis}
# Análise temporal dos documentos
yearly_data <- data %>%
  count(ano) %>%
  arrange(ano)

ggplot(yearly_data, aes(x = ano, y = n)) +
  geom_bar(stat = "identity", fill = "steelblue") +
  labs(title = "Distribuição Anual de Documentos Legislativos",
       x = "Ano", y = "Número de Documentos") +
  theme_minimal()
```

## Distribuição por Tipo

```{r type-analysis}
type_data <- data %>%
  count(tipo, sort = TRUE) %>%
  mutate(percent = n / sum(n) * 100)

kable(type_data, 
      col.names = c("Tipo", "Quantidade", "Porcentagem (%)"),
      caption = "Distribuição por Tipo de Documento")
```

# Conclusões

Este relatório demonstra a diversidade e volume da produção legislativa brasileira em múltiplos níveis de governo.

---

**Nota:** Dados obtidos de APIs oficiais do governo brasileiro. Para uso acadêmico, sempre verificar as fontes originais.
'
  
  return(rmd_content)
}