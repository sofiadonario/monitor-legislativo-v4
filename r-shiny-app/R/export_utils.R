# Export Utilities Module for Monitor Legislativo v4
# Handles data export functionality (CSV, Excel, citations)

library(openxlsx)
library(readr)
library(dplyr)

#' Export documents to CSV format
#' @param documents Data frame with document data
#' @param filename Base filename (without extension)
#' @param include_metadata Whether to include all metadata columns
#' @return Path to the created CSV file
export_to_csv <- function(documents, filename = "legislative_documents", include_metadata = TRUE) {
  if (is.null(documents) || nrow(documents) == 0) {
    return(NULL)
  }
  
  tryCatch({
    # Create exports directory if it doesn't exist
    export_dir <- file.path("exports")
    if (!dir.exists(export_dir)) {
      dir.create(export_dir, recursive = TRUE)
    }
    
    # Prepare data for export
    if (include_metadata) {
      export_data <- documents %>%
        select(titulo, tipo, estado, data_publicacao, url, urn, everything())
    } else {
      export_data <- documents %>%
        select(titulo, tipo, estado, data_publicacao, url, urn)
    }
    
    # Clean data for export
    export_data <- export_data %>%
      mutate(
        titulo = ifelse(is.na(titulo), "", titulo),
        tipo = ifelse(is.na(tipo), "", tipo),
        estado = ifelse(is.na(estado), "", estado),
        data_publicacao = as.character(data_publicacao),
        url = ifelse(is.na(url), "", url),
        urn = ifelse(is.na(urn), "", urn)
      )
    
    # Generate timestamp for filename
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    csv_filename <- paste0(filename, "_", timestamp, ".csv")
    csv_path <- file.path(export_dir, csv_filename)
    
    # Write CSV file
    write_csv(export_data, csv_path)
    
    cat("CSV export created:", csv_path, "\n")
    return(csv_path)
    
  }, error = function(e) {
    cat("Error exporting to CSV:", e$message, "\n")
    return(NULL)
  })
}

#' Export documents to Excel format
#' @param documents Data frame with document data
#' @param filename Base filename (without extension)
#' @param include_metadata Whether to include all metadata columns
#' @return Path to the created Excel file
export_to_excel <- function(documents, filename = "legislative_documents", include_metadata = TRUE) {
  if (is.null(documents) || nrow(documents) == 0) {
    return(NULL)
  }
  
  tryCatch({
    # Create exports directory if it doesn't exist
    export_dir <- file.path("exports")
    if (!dir.exists(export_dir)) {
      dir.create(export_dir, recursive = TRUE)
    }
    
    # Prepare data for export
    if (include_metadata) {
      export_data <- documents %>%
        select(titulo, tipo, estado, data_publicacao, url, urn, everything())
    } else {
      export_data <- documents %>%
        select(titulo, tipo, estado, data_publicacao, url, urn)
    }
    
    # Clean data for export
    export_data <- export_data %>%
      mutate(
        titulo = ifelse(is.na(titulo), "", titulo),
        tipo = ifelse(is.na(tipo), "", tipo),
        estado = ifelse(is.na(estado), "", estado),
        data_publicacao = as.character(data_publicacao),
        url = ifelse(is.na(url), "", url),
        urn = ifelse(is.na(urn), "", urn)
      )
    
    # Generate timestamp for filename
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    excel_filename <- paste0(filename, "_", timestamp, ".xlsx")
    excel_path <- file.path(export_dir, excel_filename)
    
    # Create workbook
    wb <- createWorkbook()
    
    # Add main data sheet
    addWorksheet(wb, "Legislative Documents")
    writeData(wb, "Legislative Documents", export_data, startRow = 1)
    
    # Add summary sheet
    addWorksheet(wb, "Summary")
    summary_data <- data.frame(
      Metric = c("Total Documents", "Date Range", "States Represented", "Document Types", "Export Date"),
      Value = c(
        nrow(documents),
        if (nrow(documents) > 0 && "data_publicacao" %in% names(documents)) {
          paste(min(documents$data_publicacao, na.rm = TRUE), "to", max(documents$data_publicacao, na.rm = TRUE))
        } else {
          "N/A"
        },
        if (nrow(documents) > 0 && "estado" %in% names(documents)) {
          length(unique(documents$estado[!is.na(documents$estado) & documents$estado != ""]))
        } else {
          0
        },
        if (nrow(documents) > 0 && "tipo" %in% names(documents)) {
          length(unique(documents$tipo[!is.na(documents$tipo) & documents$tipo != ""]))
        } else {
          0
        },
        format(Sys.time(), "%Y-%m-%d %H:%M:%S")
      )
    )
    writeData(wb, "Summary", summary_data, startRow = 1)
    
    # Style the headers
    headerStyle <- createStyle(textDecoration = "bold", fgFill = "#E6E6FA")
    addStyle(wb, "Legislative Documents", headerStyle, rows = 1, cols = 1:ncol(export_data))
    addStyle(wb, "Summary", headerStyle, rows = 1, cols = 1:2)
    
    # Save workbook
    saveWorkbook(wb, excel_path, overwrite = TRUE)
    
    cat("Excel export created:", excel_path, "\n")
    return(excel_path)
    
  }, error = function(e) {
    cat("Error exporting to Excel:", e$message, "\n")
    return(NULL)
  })
}

#' Generate academic citations for documents
#' @param documents Data frame with document data
#' @param format Citation format ("ABNT", "APA", "simple")
#' @return Character vector with formatted citations
generate_citations <- function(documents, format = "ABNT") {
  if (is.null(documents) || nrow(documents) == 0) {
    return(character())
  }
  
  citations <- sapply(1:nrow(documents), function(i) {
    doc <- documents[i, ]
    
    titulo <- if (!is.na(doc$titulo) && doc$titulo != "") doc$titulo else "[No title]"
    tipo <- if (!is.na(doc$tipo) && doc$tipo != "") doc$tipo else "Document"
    estado <- if (!is.na(doc$estado) && doc$estado != "") doc$estado else "BR"
    data_pub <- if (!is.na(doc$data_publicacao)) as.character(doc$data_publicacao) else "[No date]"
    url <- if (!is.na(doc$url) && doc$url != "") doc$url else ""
    urn <- if (!is.na(doc$urn) && doc$urn != "") doc$urn else ""
    
    switch(format,
      "ABNT" = {
        citation <- paste0(
          toupper(estado), ". ",
          titulo, ". ",
          stringr::str_to_title(tipo), ". ",
          data_pub, ". "
        )
        if (url != "") {
          citation <- paste0(citation, "Available at: ", url, ". ")
        }
        if (urn != "") {
          citation <- paste0(citation, "URN: ", urn, ".")
        }
        citation
      },
      "APA" = {
        citation <- paste0(
          estado, " (", format(as.Date(data_pub), "%Y"), "). ",
          titulo, ". ",
          stringr::str_to_title(tipo), "."
        )
        if (url != "") {
          citation <- paste0(citation, " Retrieved from ", url)
        }
        citation
      },
      "simple" = {
        citation <- paste0(
          titulo, " (", tipo, ", ", estado, ", ", data_pub, ")"
        )
        if (urn != "") {
          citation <- paste0(citation, " - URN: ", urn)
        }
        citation
      },
      {
        # Default to simple format
        paste0(titulo, " (", tipo, ", ", estado, ", ", data_pub, ")")
      }
    )
  })
  
  return(citations)
}

#' Create citation file
#' @param documents Data frame with document data
#' @param format Citation format ("ABNT", "APA", "simple")
#' @param filename Base filename (without extension)
#' @return Path to the created citation file
export_citations <- function(documents, format = "ABNT", filename = "legislative_citations") {
  if (is.null(documents) || nrow(documents) == 0) {
    return(NULL)
  }
  
  tryCatch({
    # Create exports directory if it doesn't exist
    export_dir <- file.path("exports")
    if (!dir.exists(export_dir)) {
      dir.create(export_dir, recursive = TRUE)
    }
    
    # Generate citations
    citations <- generate_citations(documents, format)
    
    # Create citation content
    citation_content <- c(
      paste0("# Legislative Document Citations - ", format, " Format"),
      paste0("# Generated on: ", format(Sys.time(), "%Y-%m-%d %H:%M:%S")),
      paste0("# Total documents: ", length(citations)),
      "",
      "## References",
      "",
      paste0(seq_along(citations), ". ", citations)
    )
    
    # Generate timestamp for filename
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    citation_filename <- paste0(filename, "_", format, "_", timestamp, ".txt")
    citation_path <- file.path(export_dir, citation_filename)
    
    # Write citation file
    writeLines(citation_content, citation_path)
    
    cat("Citation file created:", citation_path, "\n")
    return(citation_path)
    
  }, error = function(e) {
    cat("Error creating citation file:", e$message, "\n")
    return(NULL)
  })
}

#' Clean up old export files (older than 7 days)
#' @param max_age_days Maximum age in days (default: 7)
cleanup_old_exports <- function(max_age_days = 7) {
  export_dir <- file.path("exports")
  if (!dir.exists(export_dir)) {
    return()
  }
  
  tryCatch({
    files <- list.files(export_dir, full.names = TRUE)
    cutoff_date <- Sys.time() - (max_age_days * 24 * 60 * 60)
    
    for (file in files) {
      if (file.info(file)$mtime < cutoff_date) {
        unlink(file)
        cat("Removed old export file:", file, "\n")
      }
    }
    
  }, error = function(e) {
    cat("Error cleaning up exports:", e$message, "\n")
  })
}