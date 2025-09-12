#' @title Funções de Citação do Monitor Legislativo
#' @description Funções para gerar citações acadêmicas ABNT e bibliografias para documentos legislativos
#' @author Monitor Legislativo Research Team
#' @importFrom dplyr tibble bind_rows filter arrange select mutate
#' @importFrom purrr map_chr map_dfr safely
#' @importFrom stringr str_trim str_to_upper str_to_title str_replace_all str_detect
#' @importFrom lubridate ymd year
#' @importFrom cli cli_alert_info cli_alert_success cli_alert_error
#' @importFrom glue glue

#' Gerar citações ABNT para documentos legislativos
#'
#' @description
#' Gera citações no formato ABNT (Associação Brasileira de Normas Técnicas)
#' para documentos legislativos brasileiros, seguindo as normas acadêmicas.
#'
#' @param documents tibble ou vector. Documentos ou IDs para citar.
#' @param citation_style String. Estilo de citação: "abnt", "apa", "chicago", "vancouver".
#' @param format String. Formato de saída: "text", "bibtex", "ris", "endnote".
#' @param include_urls Logical. Incluir URLs nas citações.
#' @param include_access_date Logical. Incluir data de acesso.
#' @param language String. Idioma das citações: "pt", "en".
#' 
#' @return Vector ou tibble com citações formatadas.
#' 
#' @examples
#' \dontrun{
#' # Buscar documentos e gerar citações
#' docs <- ml_search("lei de licitações", limit = 5)
#' citations <- ml_generate_citations(docs)
#' 
#' # Citações em formato específico
#' bibtex_citations <- ml_generate_citations(
#'   documents = docs,
#'   citation_style = "abnt",
#'   format = "bibtex"
#' )
#' 
#' # Citações por IDs
#' doc_ids <- c("doc_123", "doc_456")
#' citations <- ml_generate_citations(
#'   documents = doc_ids,
#'   include_urls = TRUE,
#'   include_access_date = TRUE
#' )
#' 
#' # Citações em inglês
#' en_citations <- ml_generate_citations(
#'   documents = docs,
#'   citation_style = "apa",
#'   language = "en"
#' )
#' }
#' 
#' @export
ml_generate_citations <- function(documents,
                                 citation_style = "abnt",
                                 format = "text",
                                 include_urls = TRUE,
                                 include_access_date = TRUE,
                                 language = "pt") {
  
  # Validar parâmetros
  if (!citation_style %in% c("abnt", "apa", "chicago", "vancouver")) {
    stop("citation_style deve ser um de: 'abnt', 'apa', 'chicago', 'vancouver'")
  }
  
  if (!format %in% c("text", "bibtex", "ris", "endnote")) {
    stop("format deve ser um de: 'text', 'bibtex', 'ris', 'endnote'")
  }
  
  if (!language %in% c("pt", "en")) {
    stop("language deve ser um de: 'pt', 'en'")
  }
  
  # Processar entrada
  if (is.character(documents)) {
    # Se são IDs, buscar documentos
    cli_alert_info("Recuperando documentos para citação...")
    doc_data <- ml_get_documents(documents, include_content = FALSE)
  } else if (is.data.frame(documents)) {
    # Se já são dados de documentos
    doc_data <- documents
  } else {
    stop("documents deve ser um vector de IDs ou tibble de documentos")
  }
  
  if (nrow(doc_data) == 0) {
    cli_alert_error("Nenhum documento encontrado para citação")
    return(character(0))
  }
  
  cli_alert_info(glue("Gerando {nrow(doc_data)} citações no formato {citation_style}"))
  
  # Preparar requisição para API
  request_body <- list(
    documents = doc_data,
    citation_style = citation_style,
    format = format,
    include_urls = include_urls,
    include_access_date = include_access_date,
    language = language,
    access_date = as.character(Sys.Date())
  )
  
  tryCatch({
    result <- .ml_api_call("POST", "/citations/generate", body = request_body)
    
    if (is.null(result) || !result$success) {
      # Fallback: gerar citações localmente
      cli_alert_info("Gerando citações localmente...")
      return(.generate_citations_local(doc_data, citation_style, format, include_urls, include_access_date, language))
    }
    
    citations_data <- result$data %||% list()
    
    if (length(citations_data) == 0) {
      return(character(0))
    }
    
    # Processar resultado baseado no formato
    if (format == "text") {
      citations <- map_chr(citations_data, function(citation) {
        as.character(citation$formatted_citation %||% "")
      })
      
      # Adicionar metadados
      attr(citations, "citation_style") <- citation_style
      attr(citations, "language") <- language
      attr(citations, "generated_at") <- Sys.time()
      
      return(citations)
      
    } else {
      # Para formatos estruturados (bibtex, ris, etc.)
      formatted_citations <- map_chr(citations_data, function(citation) {
        as.character(citation$formatted_citation %||% "")
      })
      
      return(formatted_citations)
    }
    
  }, error = function(e) {
    cli_alert_error(glue("Erro na API de citações: {e$message}"))
    cli_alert_info("Gerando citações localmente...")
    return(.generate_citations_local(doc_data, citation_style, format, include_urls, include_access_date, language))
  })
}

# Função interna para gerar citações localmente
.generate_citations_local <- function(doc_data, citation_style, format, include_urls, include_access_date, language) {
  
  citations <- map_chr(1:nrow(doc_data), function(i) {
    doc <- doc_data[i, ]
    
    # Extrair e limpar informações do documento
    title <- str_trim(doc$title %||% "")
    author <- str_trim(doc$author %||% "")
    date <- str_trim(doc$date %||% "")
    state <- str_trim(doc$state %||% "")
    municipality <- str_trim(doc$municipality %||% "")
    category <- str_trim(doc$category %||% "")
    url <- str_trim(doc$url %||% "")
    
    # Processar ano
    year_pub <- ""
    if (nchar(date) > 0) {
      tryCatch({
        parsed_date <- ymd(date)
        if (!is.na(parsed_date)) {
          year_pub <- as.character(year(parsed_date))
        }
      }, error = function(e) {
        # Tentar extrair ano do string
        year_match <- str_extract(date, "\\d{4}")
        if (!is.na(year_match)) {
          year_pub <- year_match
        }
      })
    }
    
    # Gerar citação baseada no estilo
    if (citation_style == "abnt") {
      citation <- .format_abnt_citation(title, author, year_pub, state, municipality, category, url, include_urls, include_access_date, language)
    } else if (citation_style == "apa") {
      citation <- .format_apa_citation(title, author, year_pub, state, municipality, category, url, include_urls, include_access_date, language)
    } else if (citation_style == "chicago") {
      citation <- .format_chicago_citation(title, author, year_pub, state, municipality, category, url, include_urls, include_access_date, language)
    } else if (citation_style == "vancouver") {
      citation <- .format_vancouver_citation(title, author, year_pub, state, municipality, category, url, include_urls, include_access_date, language)
    }
    
    # Converter para formato específico se necessário
    if (format == "bibtex") {
      citation <- .convert_to_bibtex(citation, doc, i)
    } else if (format == "ris") {
      citation <- .convert_to_ris(citation, doc, i)
    } else if (format == "endnote") {
      citation <- .convert_to_endnote(citation, doc, i)
    }
    
    return(citation)
  })
  
  return(citations)
}

# Funções internas para formatação de citações

.format_abnt_citation <- function(title, author, year, state, municipality, category, url, include_urls, include_access_date, language) {
  
  # Formato ABNT para legislação
  citation_parts <- c()
  
  # Jurisdição (Estado ou Município)
  if (nchar(municipality) > 0) {
    jurisdiction <- str_to_upper(municipality)
  } else if (nchar(state) > 0) {
    jurisdiction <- str_to_upper(state)
  } else {
    jurisdiction <- "BRASIL"
  }
  
  citation_parts <- c(citation_parts, paste0(jurisdiction, "."))
  
  # Título
  if (nchar(title) > 0) {
    formatted_title <- paste0("**", str_to_title(title), "**")
    citation_parts <- c(citation_parts, formatted_title)
  }
  
  # Ano
  if (nchar(year) > 0) {
    citation_parts <- c(citation_parts, paste0(year, "."))
  }
  
  # URL e data de acesso
  if (include_urls && nchar(url) > 0) {
    url_part <- glue("Disponível em: {url}")
    citation_parts <- c(citation_parts, url_part)
    
    if (include_access_date) {
      access_text <- if (language == "pt") "Acesso em" else "Accessed"
      access_date <- format(Sys.Date(), "%d %b. %Y")
      citation_parts <- c(citation_parts, glue("{access_text}: {access_date}."))
    }
  }
  
  return(paste(citation_parts, collapse = " "))
}

.format_apa_citation <- function(title, author, year, state, municipality, category, url, include_urls, include_access_date, language) {
  
  citation_parts <- c()
  
  # Autor/Jurisdição
  if (nchar(author) > 0) {
    citation_parts <- c(citation_parts, paste0(author, "."))
  } else {
    jurisdiction <- if (nchar(municipality) > 0) municipality else state
    if (nchar(jurisdiction) > 0) {
      citation_parts <- c(citation_parts, paste0(jurisdiction, "."))
    }
  }
  
  # Ano
  if (nchar(year) > 0) {
    citation_parts <- c(citation_parts, paste0("(", year, ")."))
  }
  
  # Título
  if (nchar(title) > 0) {
    citation_parts <- c(citation_parts, paste0("*", title, "*."))
  }
  
  # URL
  if (include_urls && nchar(url) > 0) {
    citation_parts <- c(citation_parts, glue("Retrieved from {url}"))
  }
  
  return(paste(citation_parts, collapse = " "))
}

.format_chicago_citation <- function(title, author, year, state, municipality, category, url, include_urls, include_access_date, language) {
  
  citation_parts <- c()
  
  # Título
  if (nchar(title) > 0) {
    citation_parts <- c(citation_parts, paste0("\"", title, ".\""))
  }
  
  # Jurisdição
  jurisdiction <- if (nchar(municipality) > 0) municipality else state
  if (nchar(jurisdiction) > 0) {
    citation_parts <- c(citation_parts, jurisdiction)
  }
  
  # Ano
  if (nchar(year) > 0) {
    citation_parts <- c(citation_parts, paste0(year, "."))
  }
  
  # URL
  if (include_urls && nchar(url) > 0) {
    citation_parts <- c(citation_parts, url)
  }
  
  return(paste(citation_parts, collapse = " "))
}

.format_vancouver_citation <- function(title, author, year, state, municipality, category, url, include_urls, include_access_date, language) {
  
  citation_parts <- c()
  
  # Autor/Jurisdição
  if (nchar(author) > 0) {
    citation_parts <- c(citation_parts, author)
  } else {
    jurisdiction <- if (nchar(municipality) > 0) municipality else state
    if (nchar(jurisdiction) > 0) {
      citation_parts <- c(citation_parts, jurisdiction)
    }
  }
  
  # Título
  if (nchar(title) > 0) {
    citation_parts <- c(citation_parts, title)
  }
  
  # Ano
  if (nchar(year) > 0) {
    citation_parts <- c(citation_parts, year)
  }
  
  # URL
  if (include_urls && nchar(url) > 0) {
    url_text <- if (language == "pt") "Disponível em" else "Available from"
    citation_parts <- c(citation_parts, glue("{url_text}: {url}"))
  }
  
  return(paste(citation_parts, collapse = "; "))
}

# Funções de conversão para formatos estruturados

.convert_to_bibtex <- function(citation, doc, index) {
  
  # Gerar entrada BibTeX
  key <- glue("legislativo_{doc$id %||% index}")
  title <- str_replace_all(doc$title %||% "", "\\{|\\}", "")
  author <- doc$author %||% doc$state %||% "Brasil"
  year <- str_extract(doc$date %||% "", "\\d{4}") %||% ""
  url <- doc$url %||% ""
  
  bibtex_entry <- glue(
    "@misc{{{key},
  title={{{title}}},
  author={{{author}}},
  year={{{year}}},
  url={{{url}}},
  note={{Documento legislativo brasileiro}}
}}"
  )
  
  return(bibtex_entry)
}

.convert_to_ris <- function(citation, doc, index) {
  
  # Gerar entrada RIS
  ris_entry <- glue(
    "TY  - LEGAL
TI  - {doc$title %||% ''}
AU  - {doc$author %||% doc$state %||% 'Brasil'}
PY  - {str_extract(doc$date %||% '', '\\d{4}') %||% ''}
UR  - {doc$url %||% ''}
N1  - Documento legislativo brasileiro
ER  - "
  )
  
  return(ris_entry)
}

.convert_to_endnote <- function(citation, doc, index) {
  
  # Gerar entrada EndNote
  endnote_entry <- glue(
    "%0 Legal Document
%T {doc$title %||% ''}
%A {doc$author %||% doc$state %||% 'Brasil'}
%D {str_extract(doc$date %||% '', '\\d{4}') %||% ''}
%U {doc$url %||% ''}
%X Documento legislativo brasileiro"
  )
  
  return(endnote_entry)
}

#' Criar bibliografia para conjunto de documentos
#'
#' @description
#' Gera uma bibliografia completa e formatada para um conjunto de documentos
#' legislativos, organizando as citações de forma acadêmica.
#'
#' @param documents tibble ou vector. Documentos ou IDs para incluir na bibliografia.
#' @param title String. Título da bibliografia.
#' @param citation_style String. Estilo de citação.
#' @param sort_by String. Critério de ordenação: "author", "title", "date", "relevance".
#' @param group_by String. Agrupamento: "none", "category", "state", "year".
#' @param format String. Formato de saída: "text", "html", "markdown", "latex".
#' @param include_summary Logical. Incluir resumo estatístico.
#' 
#' @return String ou list com bibliografia formatada.
#' 
#' @examples
#' \dontrun{
#' # Buscar documentos e criar bibliografia
#' docs <- ml_search("sustentabilidade", limit = 20)
#' bibliography <- ml_create_bibliography(
#'   documents = docs,
#'   title = "Bibliografia sobre Sustentabilidade na Legislação Brasileira",
#'   sort_by = "date",
#'   group_by = "category"
#' )
#' 
#' # Bibliografia em HTML
#' html_bib <- ml_create_bibliography(
#'   documents = docs,
#'   format = "html",
#'   include_summary = TRUE
#' )
#' 
#' # Bibliografia agrupada por estado
#' state_bib <- ml_create_bibliography(
#'   documents = docs,
#'   group_by = "state",
#'   sort_by = "title"
#' )
#' }
#' 
#' @export
ml_create_bibliography <- function(documents,
                                  title = "Bibliografia de Documentos Legislativos",
                                  citation_style = "abnt",
                                  sort_by = "author",
                                  group_by = "none",
                                  format = "text",
                                  include_summary = TRUE) {
  
  # Validar parâmetros
  if (!sort_by %in% c("author", "title", "date", "relevance")) {
    stop("sort_by deve ser um de: 'author', 'title', 'date', 'relevance'")
  }
  
  if (!group_by %in% c("none", "category", "state", "year")) {
    stop("group_by deve ser um de: 'none', 'category', 'state', 'year'")
  }
  
  if (!format %in% c("text", "html", "markdown", "latex")) {
    stop("format deve ser um de: 'text', 'html', 'markdown', 'latex'")
  }
  
  # Processar documentos
  if (is.character(documents)) {
    doc_data <- ml_get_documents(documents, include_content = FALSE)
  } else {
    doc_data <- documents
  }
  
  if (nrow(doc_data) == 0) {
    return("")
  }
  
  cli_alert_info(glue("Criando bibliografia com {nrow(doc_data)} documentos"))
  
  # Gerar citações
  citations <- ml_generate_citations(
    documents = doc_data,
    citation_style = citation_style,
    format = "text"
  )
  
  # Adicionar citações aos dados
  doc_data$citation <- citations
  
  # Ordenar documentos
  if (sort_by == "author") {
    doc_data <- doc_data %>% arrange(author, title)
  } else if (sort_by == "title") {
    doc_data <- doc_data %>% arrange(title)
  } else if (sort_by == "date") {
    doc_data <- doc_data %>% arrange(desc(date))
  } else if (sort_by == "relevance" && "relevance_score" %in% names(doc_data)) {
    doc_data <- doc_data %>% arrange(desc(relevance_score))
  }
  
  # Criar bibliografia
  bibliography_content <- .format_bibliography(doc_data, title, group_by, format, include_summary)
  
  return(bibliography_content)
}

# Função interna para formatação da bibliografia
.format_bibliography <- function(doc_data, title, group_by, format, include_summary) {
  
  bibliography_parts <- c()
  
  # Cabeçalho
  if (format == "html") {
    bibliography_parts <- c(bibliography_parts, glue("<h1>{title}</h1>"))
    if (include_summary) {
      summary_text <- glue("<p>Total de documentos: {nrow(doc_data)} | Gerado em: {Sys.Date()}</p>")
      bibliography_parts <- c(bibliography_parts, summary_text)
    }
  } else if (format == "markdown") {
    bibliography_parts <- c(bibliography_parts, glue("# {title}"))
    if (include_summary) {
      summary_text <- glue("**Total de documentos:** {nrow(doc_data)} | **Gerado em:** {Sys.Date()}")
      bibliography_parts <- c(bibliography_parts, summary_text)
    }
  } else if (format == "latex") {
    bibliography_parts <- c(bibliography_parts, glue("\\section{{{title}}}"))
    if (include_summary) {
      summary_text <- glue("Total de documentos: {nrow(doc_data)}. Gerado em: {Sys.Date()}.")
      bibliography_parts <- c(bibliography_parts, summary_text)
    }
  } else {
    bibliography_parts <- c(bibliography_parts, title)
    bibliography_parts <- c(bibliography_parts, str_repeat("=", nchar(title)))
    if (include_summary) {
      summary_text <- glue("Total de documentos: {nrow(doc_data)} | Gerado em: {Sys.Date()}")
      bibliography_parts <- c(bibliography_parts, summary_text)
    }
  }
  
  bibliography_parts <- c(bibliography_parts, "")
  
  # Agrupar se necessário
  if (group_by == "none") {
    # Lista simples
    for (i in 1:nrow(doc_data)) {
      citation_entry <- .format_citation_entry(doc_data[i, ], i, format)
      bibliography_parts <- c(bibliography_parts, citation_entry)
    }
  } else {
    # Agrupamento
    if (group_by == "category") {
      groups <- split(doc_data, doc_data$category)
    } else if (group_by == "state") {
      groups <- split(doc_data, doc_data$state)
    } else if (group_by == "year") {
      doc_data$year <- str_extract(doc_data$date, "\\d{4}")
      groups <- split(doc_data, doc_data$year)
    }
    
    for (group_name in names(groups)) {
      group_data <- groups[[group_name]]
      
      # Cabeçalho do grupo
      if (format == "html") {
        group_header <- glue("<h2>{group_name}</h2>")
      } else if (format == "markdown") {
        group_header <- glue("## {group_name}")
      } else if (format == "latex") {
        group_header <- glue("\\subsection{{{group_name}}}")
      } else {
        group_header <- glue("\n{group_name}")
        group_header <- c(group_header, str_repeat("-", nchar(group_name)))
      }
      
      bibliography_parts <- c(bibliography_parts, group_header, "")
      
      # Citações do grupo
      for (i in 1:nrow(group_data)) {
        citation_entry <- .format_citation_entry(group_data[i, ], i, format)
        bibliography_parts <- c(bibliography_parts, citation_entry)
      }
      
      bibliography_parts <- c(bibliography_parts, "")
    }
  }
  
  return(paste(bibliography_parts, collapse = "\n"))
}

.format_citation_entry <- function(doc_row, index, format) {
  
  citation <- doc_row$citation
  
  if (format == "html") {
    return(glue("<p>{index}. {citation}</p>"))
  } else if (format == "markdown") {
    return(glue("{index}. {citation}"))
  } else if (format == "latex") {
    return(glue("\\item {citation}"))
  } else {
    return(glue("{index}. {citation}"))
  }
}

#' Exportar bibliografia para arquivo
#'
#' @description
#' Exporta bibliografia em formato BibTeX, RIS ou EndNote para uso em
#' gerenciadores de referência como Zotero, Mendeley ou EndNote.
#'
#' @param documents tibble ou vector. Documentos para exportar.
#' @param file_path String. Caminho do arquivo de saída.
#' @param format String. Formato de exportação: "bibtex", "ris", "endnote".
#' @param encoding String. Codificação do arquivo: "UTF-8", "latin1".
#' 
#' @return Logical. TRUE se exportação bem-sucedida.
#' 
#' @examples
#' \dontrun{
#' # Buscar documentos e exportar para BibTeX
#' docs <- ml_search("energia renovável", limit = 30)
#' 
#' # Exportar para BibTeX
#' ml_export_bibtex(
#'   documents = docs,
#'   file_path = "renewable_energy_legislation.bib",
#'   format = "bibtex"
#' )
#' 
#' # Exportar para RIS (Zotero/Mendeley)
#' ml_export_bibtex(
#'   documents = docs,
#'   file_path = "renewable_energy_legislation.ris",
#'   format = "ris"
#' )
#' 
#' # Exportar para EndNote
#' ml_export_bibtex(
#'   documents = docs,
#'   file_path = "renewable_energy_legislation.txt",
#'   format = "endnote"
#' )
#' }
#' 
#' @export
ml_export_bibtex <- function(documents,
                             file_path,
                             format = "bibtex",
                             encoding = "UTF-8") {
  
  if (!format %in% c("bibtex", "ris", "endnote")) {
    stop("format deve ser um de: 'bibtex', 'ris', 'endnote'")
  }
  
  # Processar documentos
  if (is.character(documents)) {
    doc_data <- ml_get_documents(documents, include_content = FALSE)
  } else {
    doc_data <- documents
  }
  
  if (nrow(doc_data) == 0) {
    cli_alert_error("Nenhum documento para exportar")
    return(FALSE)
  }
  
  cli_alert_info(glue("Exportando {nrow(doc_data)} documentos para {format}"))
  
  tryCatch({
    # Gerar citações no formato apropriado
    citations <- ml_generate_citations(
      documents = doc_data,
      citation_style = "abnt",
      format = format
    )
    
    # Criar conteúdo do arquivo
    if (format == "bibtex") {
      file_content <- paste(citations, collapse = "\n\n")
    } else if (format == "ris") {
      file_content <- paste(citations, collapse = "\n\n")
    } else if (format == "endnote") {
      file_content <- paste(citations, collapse = "\n\n")
    }
    
    # Escrever arquivo
    writeLines(file_content, file_path, useBytes = TRUE)
    
    cli_alert_success(glue("Bibliografia exportada para: {file_path}"))
    
    return(TRUE)
    
  }, error = function(e) {
    cli_alert_error(glue("Erro na exportação: {e$message}"))
    return(FALSE)
  })
}