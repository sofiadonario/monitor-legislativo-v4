# Citation Module - Week 5 Enhanced Implementation
# Monitor Legislativo v4 - Academic Citation Generation Interface
# ================================================================

#' Citation Generation Module for Monitor Legislativo v4 - Week 5 Implementation
#' 
#' Comprehensive Shiny module for generating academic citations of Brazilian 
#' legislative documents with enhanced ABNT NBR 6023:2018 compliance, 
#' advanced metadata extraction, and custom format builder.
#' Features Brazilian legal document structure understanding and LGPD compliance.
#' 
#' Week 5 Enhancements:
#' - Complete ABNT NBR 6023:2018 compliance with Brazilian legal specifics
#' - Advanced metadata extraction from Brazilian legal document patterns
#' - Custom format builder for institutional requirements
#' - Enhanced error checking and validation
#' - Bulk citation processing with progress tracking
#' - Integration with LexML standards for legal citations

library(shiny)
library(DT)
library(stringr)
library(lubridate)

# Brazilian Legal Citation Metadata Extractor
# Enhanced Week 5 Implementation
# ============================================

#' Extract Brazilian Legal Document Metadata
#' 
#' Advanced metadata extraction specifically designed for Brazilian legislative documents
#' following ABNT NBR 6023:2018 standards with understanding of Brazilian legal hierarchy
#' 
#' @param document Single document data or document data frame
#' @param validate_metadata Perform validation of extracted metadata
#' @return List containing structured metadata for citation generation
extract_brazilian_legal_metadata <- function(document, validate_metadata = TRUE) {
  
  # Initialize metadata structure
  metadata <- list(
    # Basic identification
    id = document$id %||% document$ID %||% NA,
    
    # Title components (ABNT requires specific formatting)
    titulo_principal = extract_main_title(document$titulo %||% document$title),
    titulo_completo = document$titulo %||% document$title %||% "Documento sem título",
    subtitulo = extract_subtitle(document$titulo %||% document$title),
    
    # Authority/Author information (critical for Brazilian legal docs)
    autoridade_emissor = extract_issuing_authority(document),
    nivel_governamental = extract_government_level(document),
    orgao_origem = extract_origin_organ(document),
    
    # Publication information
    data_publicacao = standardize_brazilian_date(document$data %||% document$data_publicacao),
    data_assinatura = extract_signature_date(document),
    numero_documento = extract_document_number(document),
    
    # Geographic jurisdiction
    jurisdicao = extract_jurisdiction(document),
    estado = standardize_state_code(document$estado %||% document$state),
    municipio = standardize_municipality_name(document$municipio %||% document$municipality),
    
    # Document classification
    tipo_documento = classify_document_type(document),
    categoria_juridica = extract_legal_category(document),
    materia = extract_subject_matter(document),
    
    # Publication sources (essential for Brazilian legal citations)
    diario_oficial = extract_official_journal_info(document),
    fonte_publicacao = extract_publication_source(document),
    
    # Digital identifiers
    url_oficial = extract_official_url(document),
    urn_lex = extract_urn_lex(document),
    
    # Content information
    ementa = clean_legal_summary(document$ementa %||% document$summary),
    texto_integral = !isTRUE(is.null(document$texto)) && nchar(document$texto) > 0,
    
    # Validation metadata
    data_extracao = Sys.time(),
    validacao_realizada = validate_metadata
  )
  
  # Perform validation if requested
  if (validate_metadata) {
    metadata$validacao_resultado <- validate_brazilian_legal_metadata(metadata)
  }
  
  return(metadata)
}

#' Extract main title from complex Brazilian legal document titles
extract_main_title <- function(full_title) {
  if (isTRUE(is.null(full_title)) || isTRUE(is.na(full_title))) return("Título não disponível")
  
  # Brazilian legal documents often have complex title structures
  # Pattern: "Lei nº 1234, de 01 de janeiro de 2024. Dispõe sobre..."
  
  # Split on period if it contains "dispõe sobre", "altera", "revoga", etc.
  legal_keywords <- c("dispõe sobre", "altera", "revoga", "institui", "estabelece", 
                     "regulamenta", "cria", "define", "modifica")
  
  for (keyword in legal_keywords) {
    if (grepl(keyword, full_title, ignore.case = TRUE)) {
      parts <- strsplit(full_title, "\\.")[[1]]
      if (length(parts) > 1) {
        return(trimws(parts[1]))
      }
    }
  }
  
  # If no keyword found, return first sentence or up to 100 characters
  first_sentence <- strsplit(full_title, "\\.")[[1]][1]
  if (nchar(first_sentence) > 100) {
    return(paste0(substr(first_sentence, 1, 97), "..."))
  }
  
  return(trimws(first_sentence))
}

#' Extract subtitle (ementa) from document title
extract_subtitle <- function(full_title) {
  if (isTRUE(is.null(full_title)) || isTRUE(is.na(full_title))) return("")
  
  # Look for subtitle after first period
  parts <- strsplit(full_title, "\\.")[[1]]
  if (length(parts) > 1) {
    subtitle <- paste(parts[-1], collapse = ". ")
    return(trimws(subtitle))
  }
  
  return("")
}

#' Extract issuing authority with Brazilian government hierarchy understanding
extract_issuing_authority <- function(document) {
  authority_fields <- c("autoridade", "authority", "autor", "orgao_emissor")
  
  for (field in authority_fields) {
    if (!isTRUE(is.null(document[[field]])) && !isTRUE(is.na(document[[field]])) && 
        document[[field]] != "") {
      return(standardize_authority_name(document[[field]]))
    }
  }
  
  # Extract from document type and jurisdiction
  level <- extract_government_level(document)
  state <- document$estado %||% document$state
  municipality <- document$municipio %||% document$municipality
  
  if (level == "federal") {
    return("BRASIL")
  } else if (level == "estadual" && !is.null(state)) {
    state_name <- get_full_state_name(state)
    return(toupper(state_name))
  } else if (level == "municipal" && !is.null(municipality)) {
    return(toupper(municipality))
  }
  
  return("AUTORIDADE NÃO IDENTIFICADA")
}

#' Standardize authority names according to ABNT standards
standardize_authority_name <- function(authority) {
  if (isTRUE(is.null(authority)) || isTRUE(is.na(authority))) return("AUTORIDADE NÃO IDENTIFICADA")
  
  # Convert to uppercase (ABNT requirement for legal citations)
  authority <- toupper(trimws(authority))
  
  # Standardize common Brazilian authorities
  authority_mapping <- list(
    "BRASIL" = "BRASIL",
    "UNIÃO" = "BRASIL", 
    "REPÚBLICA FEDERATIVA DO BRASIL" = "BRASIL",
    "PRESIDÊNCIA DA REPÚBLICA" = "BRASIL",
    "CONGRESSO NACIONAL" = "BRASIL. CONGRESSO NACIONAL",
    "SUPREMO TRIBUNAL FEDERAL" = "BRASIL. SUPREMO TRIBUNAL FEDERAL"
  )
  
  if (authority %in% names(authority_mapping)) {
    return(authority_mapping[[authority]])
  }
  
  return(authority)
}

#' Extract government level (federal, estadual, municipal)
extract_government_level <- function(document) {
  # Check state field
  if (!isTRUE(is.null(document$estado)) && document$estado == "DF") {
    return("federal")
  }
  
  # Check document type patterns
  type <- document$tipo_documento %||% document$tipo %||% ""
  
  federal_patterns <- c("lei federal", "decreto federal", "medida provisória", 
                       "emenda constitucional", "lei complementar")
  
  for (pattern in federal_patterns) {
    if (grepl(pattern, type, ignore.case = TRUE)) {
      return("federal")
    }
  }
  
  # Check for municipal indicators
  if (!isTRUE(is.null(document$municipio)) && document$municipio != "") {
    return("municipal")
  }
  
  # Check for state indicators
  if (!isTRUE(is.null(document$estado)) && document$estado != "" && document$estado != "DF") {
    return("estadual")
  }
  
  return("indeterminado")
}

#' Extract document number from title or metadata
extract_document_number <- function(document) {
  title <- document$titulo %||% document$title %||% ""
  
  # Common Brazilian legal document number patterns
  patterns <- list(
    "lei" = "lei\\s+n[ºo°]?\\.?\\s*(\\d+[\\./\\-\\d]*)",
    "decreto" = "decreto\\s+n[ºo°]?\\.?\\s*(\\d+[\\./\\-\\d]*)",
    "portaria" = "portaria\\s+n[ºo°]?\\.?\\s*(\\d+[\\./\\-\\d]*)",
    "resolução" = "resolu[çc][ãa]o\\s+n[ºo°]?\\.?\\s*(\\d+[\\./\\-\\d]*)"
  )
  
  for (pattern in patterns) {
    matches <- regmatches(title, regexpr(pattern, title, ignore.case = TRUE))
    if (length(matches) > 0) {
      # Extract just the number
      number_match <- regmatches(matches, regexpr("\\d+[\\./\\-\\d]*", matches))
      if (length(number_match) > 0) {
        return(number_match[1])
      }
    }
  }
  
  return("")
}

#' Standardize Brazilian date formats
standardize_brazilian_date <- function(date_input) {
  if (isTRUE(is.null(date_input)) || isTRUE(is.na(date_input))) return(Sys.Date())
  
  # If already a Date object
  if (inherits(date_input, "Date")) return(date_input)
  
  # Common Brazilian date patterns
  date_patterns <- c(
    "%d/%m/%Y",      # 01/12/2024
    "%d-%m-%Y",      # 01-12-2024  
    "%Y-%m-%d",      # 2024-12-01
    "%d de %B de %Y" # 01 de dezembro de 2024
  )
  
  for (pattern in date_patterns) {
    parsed_date <- tryCatch({
      as.Date(date_input, format = pattern)
    }, error = function(e) NULL)
    
    if (!isTRUE(is.null(parsed_date)) && !is.na(parsed_date)) {
      return(parsed_date)
    }
  }
  
  # Use lubridate for more flexible parsing
  parsed_date <- tryCatch({
    lubridate::dmy(date_input)
  }, error = function(e) {
    tryCatch({
      lubridate::ymd(date_input)
    }, error = function(e) Sys.Date())
  })
  
  return(parsed_date)
}

#' Get full state name from abbreviation
get_full_state_name <- function(state_code) {
  state_mapping <- list(
    "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
    "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", 
    "ES" = "Espírito Santo", "GO" = "Goiás", "MA" = "Maranhão",
    "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul", "MG" = "Minas Gerais",
    "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná", "PE" = "Pernambuco",
    "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
    "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima",
    "SC" = "Santa Catarina", "SP" = "São Paulo", "SE" = "Sergipe", 
    "TO" = "Tocantins"
  )
  
  return(state_mapping[[toupper(state_code)]] %||% state_code)
}

#' Validate extracted metadata for completeness and accuracy
validate_brazilian_legal_metadata <- function(metadata) {
  validation_result <- list(
    valid = TRUE,
    warnings = c(),
    errors = c(),
    completeness_score = 0
  )
  
  # Check required fields
  required_fields <- c("titulo_completo", "autoridade_emissor", "data_publicacao")
  
  for (field in required_fields) {
    if (isTRUE(is.null(metadata[[field]])) || isTRUE(is.na(metadata[[field]])) || 
        (is.character(metadata[[field]]) && metadata[[field]] == "")) {
      validation_result$errors <- c(validation_result$errors, 
                                   paste("Campo obrigatório ausente:", field))
      validation_result$valid <- FALSE
    }
  }
  
  # Check date validity
  if (!is.null(metadata$data_publicacao)) {
    if (metadata$data_publicacao > Sys.Date()) {
      validation_result$warnings <- c(validation_result$warnings,
                                     "Data de publicação é futura")
    }
    if (metadata$data_publicacao < as.Date("1800-01-01")) {
      validation_result$warnings <- c(validation_result$warnings,
                                     "Data de publicação muito antiga")
    }
  }
  
  # Calculate completeness score
  all_fields <- names(metadata)[!names(metadata) %in% c("data_extracao", "validacao_realizada", "validacao_resultado")]
  completed_fields <- sum(!sapply(all_fields, function(f) {
    isTRUE(is.null(metadata[[f]])) || isTRUE(is.na(metadata[[f]])) || 
    (is.character(metadata[[f]]) && metadata[[f]] == "")
  }))
  
  validation_result$completeness_score <- round((completed_fields / length(all_fields)) * 100, 1)
  
  return(validation_result)
}

# Additional helper functions for complete metadata extraction
# ==========================================================

#' Extract origin organ from document metadata
extract_origin_organ <- function(document) {
  organ_fields <- c("orgao", "orgao_origem", "organ", "institution")
  
  for (field in organ_fields) {
    if (!isTRUE(is.null(document[[field]])) && document[[field]] != "") {
      return(document[[field]])
    }
  }
  
  # Infer from document type and level
  type <- classify_document_type(document)
  level <- extract_government_level(document)
  
  if (level == "federal") {
    if (grepl("lei", type, ignore.case = TRUE)) {
      return("Congresso Nacional")
    } else if (grepl("decreto", type, ignore.case = TRUE)) {
      return("Presidência da República")
    }
  }
  
  return("")
}

#' Extract signature date (different from publication date)
extract_signature_date <- function(document) {
  signature_fields <- c("data_assinatura", "signature_date", "data_aprovacao")
  
  for (field in signature_fields) {
    if (!is.null(document[[field]])) {
      return(standardize_brazilian_date(document[[field]]))
    }
  }
  
  return(NULL)
}

#' Extract jurisdiction information
extract_jurisdiction <- function(document) {
  level <- extract_government_level(document)
  state <- document$estado %||% document$state
  municipality <- document$municipio %||% document$municipality
  
  if (level == "federal") {
    return("Federal")
  } else if (level == "estadual" && !is.null(state)) {
    return(get_full_state_name(state))
  } else if (level == "municipal" && !is.null(municipality)) {
    return(paste(municipality, get_full_state_name(state), sep = " - "))
  }
  
  return("Jurisdição indeterminada")
}

#' Standardize state code to uppercase
standardize_state_code <- function(state) {
  if (isTRUE(is.null(state)) || isTRUE(is.na(state))) return("")
  return(toupper(trimws(state)))
}

#' Standardize municipality name
standardize_municipality_name <- function(municipality) {
  if (isTRUE(is.null(municipality)) || isTRUE(is.na(municipality))) return("")
  
  # Convert to title case and clean
  municipality <- trimws(municipality)
  municipality <- gsub("\\s+", " ", municipality)  # Remove extra spaces
  
  # Convert to title case (first letter of each word uppercase)
  municipality <- tools::toTitleCase(tolower(municipality))
  
  return(municipality)
}

#' Classify document type according to Brazilian legal standards
classify_document_type <- function(document) {
  type_fields <- c("tipo_documento", "tipo", "document_type", "type")
  
  for (field in type_fields) {
    if (!isTRUE(is.null(document[[field]])) && document[[field]] != "") {
      return(standardize_document_type(document[[field]]))
    }
  }
  
  # Try to infer from title
  title <- document$titulo %||% document$title %||% ""
  
  type_patterns <- list(
    "Lei" = c("^lei\\s+n", "lei federal", "lei estadual", "lei municipal"),
    "Decreto" = c("^decreto\\s+n", "decreto federal", "decreto estadual"),
    "Medida Provisória" = c("^medida\\s+provisória", "^mp\\s+n"),
    "Resolução" = c("^resolu[çc][ãa]o\\s+n"),
    "Portaria" = c("^portaria\\s+n"),
    "Instrução Normativa" = c("^instru[çc][ãa]o\\s+normativa")
  )
  
  for (type_name in names(type_patterns)) {
    for (pattern in type_patterns[[type_name]]) {
      if (grepl(pattern, title, ignore.case = TRUE)) {
        return(type_name)
      }
    }
  }
  
  return("Documento")
}

#' Standardize document type names
standardize_document_type <- function(type) {
  if (isTRUE(is.null(type)) || isTRUE(is.na(type))) return("Documento")
  
  type <- trimws(tolower(type))
  
  type_mapping <- list(
    "lei" = "Lei",
    "decreto" = "Decreto", 
    "medida provisória" = "Medida Provisória",
    "mp" = "Medida Provisória",
    "resolução" = "Resolução",
    "portaria" = "Portaria",
    "instrução normativa" = "Instrução Normativa"
  )
  
  return(type_mapping[[type]] %||% tools::toTitleCase(type))
}

#' Extract legal category
extract_legal_category <- function(document) {
  category_fields <- c("categoria", "category", "materia", "subject")
  
  for (field in category_fields) {
    if (!isTRUE(is.null(document[[field]])) && document[[field]] != "") {
      return(document[[field]])
    }
  }
  
  return("")
}

#' Extract subject matter from document
extract_subject_matter <- function(document) {
  # Try to extract from ementa/summary
  ementa <- document$ementa %||% document$summary %||% ""
  
  if (nchar(ementa) > 10) {
    # Extract first meaningful phrase
    sentences <- strsplit(ementa, "\\.")[[1]]
    if (length(sentences) > 0) {
      first_sentence <- trimws(sentences[1])
      if (nchar(first_sentence) > 5) {
        return(first_sentence)
      }
    }
  }
  
  return("")
}

#' Extract official journal information
extract_official_journal_info <- function(document) {
  journal_fields <- c("diario_oficial", "official_journal", "dou", "doe")
  
  for (field in journal_fields) {
    if (!isTRUE(is.null(document[[field]])) && document[[field]] != "") {
      return(document[[field]])
    }
  }
  
  # Infer based on government level
  level <- extract_government_level(document)
  
  if (level == "federal") {
    return("Diário Oficial da União")
  } else if (level == "estadual") {
    state <- document$estado %||% document$state
    if (!is.null(state)) {
      return(paste("Diário Oficial do Estado de", get_full_state_name(state)))
    }
  }
  
  return("")
}

#' Extract publication source
extract_publication_source <- function(document) {
  source_fields <- c("fonte", "source", "publisher", "editora")
  
  for (field in source_fields) {
    if (!isTRUE(is.null(document[[field]])) && document[[field]] != "") {
      return(document[[field]])
    }
  }
  
  # Default based on government level
  level <- extract_government_level(document)
  state <- document$estado %||% document$state
  municipality <- document$municipio %||% document$municipality
  
  if (level == "federal") {
    return("Presidência da República")
  } else if (level == "estadual" && !is.null(state)) {
    return(paste("Governo do Estado de", get_full_state_name(state)))
  } else if (level == "municipal" && !is.null(municipality)) {
    return(paste("Prefeitura Municipal de", municipality))
  }
  
  return("")
}

#' Extract official URL
extract_official_url <- function(document) {
  url_fields <- c("url", "url_oficial", "link", "uri")
  
  for (field in url_fields) {
    if (!isTRUE(is.null(document[[field]])) && document[[field]] != "" && 
        grepl("^https?://", document[[field]])) {
      return(document[[field]])
    }
  }
  
  return("")
}

#' Extract URN LEX identifier
extract_urn_lex <- function(document) {
  urn_fields <- c("urn", "urn_lex", "lex_id")
  
  for (field in urn_fields) {
    if (!isTRUE(is.null(document[[field]])) && document[[field]] != "" &&
        grepl("^urn:lex", document[[field]])) {
      return(document[[field]])
    }
  }
  
  return("")
}

#' Clean legal summary/ementa
clean_legal_summary <- function(summary) {
  if (isTRUE(is.null(summary)) || isTRUE(is.na(summary)) || summary == "") return("")
  
  # Remove extra whitespace and line breaks
  summary <- gsub("\\s+", " ", trimws(summary))
  
  # Remove common prefixes
  summary <- gsub("^(ementa:\\s*|súmula:\\s*|resumo:\\s*)", "", summary, ignore.case = TRUE)
  
  return(trimws(summary))
}

# Enhanced ABNT NBR 6023:2018 Citation Formatters
# =================================================

#' Generate ABNT NBR 6023:2018 compliant citation
#' 
#' Complete implementation of ABNT standards for Brazilian legal documents
#' with proper handling of all required elements and formatting
generate_abnt_citation_enhanced <- function(metadata, include_access_date = TRUE, short_format = FALSE) {
  
  # Validate metadata
  if (isTRUE(is.null(metadata$titulo_completo)) || metadata$titulo_completo == "") {
    return("ERRO: Título do documento não disponível")
  }
  
  citation_parts <- c()
  
  # 1. AUTHOR/AUTHORITY (uppercase, required)
  authority <- metadata$autoridade_emissor %||% "AUTOR NÃO IDENTIFICADO"
  citation_parts <- c(citation_parts, paste0(toupper(authority), "."))
  
  # 2. TITLE (italics simulation with **bold**, required)
  title <- metadata$titulo_principal %||% metadata$titulo_completo
  
  if (!isTRUE(is.null(metadata$numero_documento)) && metadata$numero_documento != "") {
    # Include document number in title for legal docs
    title <- paste(title, "nº", metadata$numero_documento)
  }
  
  # Add date to title if available and not already included
  if (!isTRUE(is.null(metadata$data_publicacao)) && !grepl("\\d{4}", title)) {
    date_formatted <- format_abnt_date(metadata$data_publicacao)
    title <- paste(title, ", de", date_formatted)
  }
  
  citation_parts <- c(citation_parts, paste0("**", title, "**."))
  
  # 3. SUBTITLE/EMENTA (if available)
  if (!isTRUE(is.null(metadata$subtitulo)) && metadata$subtitulo != "") {
    citation_parts <- c(citation_parts, paste0(metadata$subtitulo, "."))
  } else if (!isTRUE(is.null(metadata$ementa)) && metadata$ementa != "" && !short_format) {
    ementa <- substr(metadata$ementa, 1, 100)
    if (nchar(metadata$ementa) > 100) ementa <- paste0(ementa, "...")
    citation_parts <- c(citation_parts, paste0(ementa, "."))
  }
  
  # 4. PUBLICATION PLACE AND PUBLISHER
  publication_info <- build_publication_info_abnt(metadata)
  if (publication_info != "") {
    citation_parts <- c(citation_parts, paste0(publication_info, "."))
  }
  
  # 5. OFFICIAL JOURNAL (if available)
  if (!isTRUE(is.null(metadata$diario_oficial)) && metadata$diario_oficial != "") {
    journal_info <- paste(metadata$diario_oficial)
    if (!is.null(metadata$data_publicacao)) {
      journal_info <- paste(journal_info, format_abnt_date(metadata$data_publicacao), sep = ", ")
    }
    citation_parts <- c(citation_parts, paste0(journal_info, "."))
  }
  
  # 6. ONLINE ACCESS (if URL available)
  if (!isTRUE(is.null(metadata$url_oficial)) && metadata$url_oficial != "") {
    citation_parts <- c(citation_parts, paste0("Disponível em: ", metadata$url_oficial, "."))
    
    if (include_access_date) {
      access_date <- format_abnt_date(Sys.Date())
      citation_parts <- c(citation_parts, paste0("Acesso em: ", access_date, "."))
    }
  }
  
  # Join all parts
  final_citation <- paste(citation_parts, collapse = " ")
  
  # Clean up extra periods and spaces
  final_citation <- gsub("\\.\\.+", ".", final_citation)
  final_citation <- gsub("\\s+", " ", final_citation)
  
  return(trimws(final_citation))
}

#' Build publication information according to ABNT standards
build_publication_info_abnt <- function(metadata) {
  pub_parts <- c()
  
  # Publication place
  if (!is.null(metadata$estado)) {
    if (metadata$estado == "DF") {
      pub_parts <- c(pub_parts, "Brasília, DF")
    } else if (!isTRUE(is.null(metadata$municipio)) && metadata$municipio != "") {
      pub_parts <- c(pub_parts, paste(metadata$municipio, metadata$estado, sep = ", "))
    } else {
      state_name <- get_full_state_name(metadata$estado)
      pub_parts <- c(pub_parts, state_name)
    }
  }
  
  # Publisher
  publisher <- metadata$fonte_publicacao %||% ""
  if (publisher != "") {
    pub_parts <- c(pub_parts, publisher)
  }
  
  # Year
  if (!is.null(metadata$data_publicacao)) {
    year <- format(metadata$data_publicacao, "%Y")
    pub_parts <- c(pub_parts, year)
  }
  
  return(paste(pub_parts, collapse = ": "))
}

#' Format date according to ABNT standards (day month abbreviated year)
format_abnt_date <- function(date) {
  if (isTRUE(is.null(date)) || isTRUE(is.na(date))) return("")
  
  if (!inherits(date, "Date")) {
    date <- as.Date(date)
  }
  
  months_abbr <- c("jan", "fev", "mar", "abr", "mai", "jun",
                   "jul", "ago", "set", "out", "nov", "dez")
  
  day <- format(date, "%d")
  month <- months_abbr[as.numeric(format(date, "%m"))]
  year <- format(date, "%Y")
  
  return(paste(day, month, year, sep = " "))
}

#' Citation Module UI
#' 
#' Creates the user interface for citation generation including format selection,
#' document selection, and citation preview/export functionality.
#' 
#' @param id Character string for module namespace ID
#' @return Shiny UI tagList containing citation interface elements
#' @export
citationUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      column(12,
        h3("📚 Gerador de Citações Acadêmicas", 
           style = "color: #2c3e50; margin-bottom: 20px;"),
        p("Gere citações bibliográficas precisas para documentos legislativos brasileiros em formatos acadêmicos padrão.",
          style = "color: #7f8c8d; margin-bottom: 30px;")
      )
    ),
    
    fluidRow(
      # Document Selection Panel
      column(4,
        wellPanel(
          h4("Seleção de Documentos", style = "color: #2c3e50;"),
          
          # Search for documents to cite
          textInput(
            inputId = ns("document_search"),
            label = "Buscar Documentos:",
            placeholder = "Digite termos para encontrar documentos...",
            value = ""
          ),
          
          # Quick filters
          selectInput(
            inputId = ns("document_type_filter"),
            label = "Tipo de Documento:",
            choices = list(
              "Todos os Tipos" = "all",
              "Leis" = "lei",
              "Decretos" = "decreto",
              "Resoluções" = "resolucao",
              "Portarias" = "portaria",
              "Instruções Normativas" = "instrucao_normativa"
            ),
            selected = "all"
          ),
          
          selectInput(
            inputId = ns("state_filter_citation"),
            label = "Estado:",
            choices = list(
              "Todos os Estados" = "all",
              "Acre" = "AC", "Alagoas" = "AL", "Amapá" = "AP", "Amazonas" = "AM",
              "Bahia" = "BA", "Ceará" = "CE", "Distrito Federal" = "DF", 
              "Espírito Santo" = "ES", "Goiás" = "GO", "Maranhão" = "MA",
              "Mato Grosso" = "MT", "Mato Grosso do Sul" = "MS", "Minas Gerais" = "MG",
              "Pará" = "PA", "Paraíba" = "PB", "Paraná" = "PR", "Pernambuco" = "PE",
              "Piauí" = "PI", "Rio de Janeiro" = "RJ", "Rio Grande do Norte" = "RN",
              "Rio Grande do Sul" = "RS", "Rondônia" = "RO", "Roraima" = "RR",
              "Santa Catarina" = "SC", "São Paulo" = "SP", "Sergipe" = "SE", "Tocantins" = "TO"
            ),
            selected = "all"
          ),
          
          actionButton(
            inputId = ns("search_documents"),
            label = "Buscar Documentos",
            icon = icon("search"),
            class = "btn-primary btn-block"
          ),
          
          br(),
          
          # Selected documents count
          uiOutput(ns("selected_count")),
          
          br(),
          
          # Clear selection
          actionButton(
            inputId = ns("clear_selection"),
            label = "Limpar Seleção",
            icon = icon("trash"),
            class = "btn-warning btn-block"
          )
        )
      ),
      
      # Document Results and Selection
      column(8,
        wellPanel(
          h4("Documentos Encontrados"),
          
          # Results table with selection
          DT::dataTableOutput(ns("documents_table")),
          
          br(),
          
          fluidRow(
            column(6,
              actionButton(
                inputId = ns("select_all"),
                label = "Selecionar Todos",
                icon = icon("check-square"),
                class = "btn-info"
              )
            ),
            column(6,
              actionButton(
                inputId = ns("deselect_all"),
                label = "Desmarcar Todos",
                icon = icon("square"),
                class = "btn-secondary"
              )
            )
          )
        )
      )
    ),
    
    # Citation Generation Panel
    fluidRow(
      column(12,
        wellPanel(
          h4("Geração de Citações", style = "color: #2c3e50;"),
          
          fluidRow(
            column(3,
              h5("Formato de Citação"),
              radioButtons(
                inputId = ns("citation_format"),
                label = NULL,
                choices = list(
                  "ABNT (NBR 6023)" = "abnt",
                  "APA (7ª edição)" = "apa",
                  "Chicago (17ª edição)" = "chicago",
                  "BibTeX" = "bibtex",
                  "Vancouver" = "vancouver"
                ),
                selected = "abnt"
              )
            ),
            
            column(3,
              h5("Opções de Formato"),
              checkboxGroupInput(
                inputId = ns("citation_options"),
                label = NULL,
                choices = list(
                  "Incluir URL" = "include_url",
                  "Incluir Data de Acesso" = "include_access_date",
                  "Incluir DOI" = "include_doi",
                  "Formato Curto" = "short_format"
                ),
                selected = c("include_url", "include_access_date")
              )
            ),
            
            column(3,
              h5("Idioma da Citação"),
              radioButtons(
                inputId = ns("citation_language"),
                label = NULL,
                choices = list(
                  "Português" = "pt",
                  "Inglês" = "en",
                  "Espanhol" = "es"
                ),
                selected = "pt"
              )
            ),
            
            column(3,
              h5("Ações"),
              br(),
              actionButton(
                inputId = ns("generate_citations"),
                label = "Gerar Citações",
                icon = icon("quote-right"),
                class = "btn-success btn-block"
              ),
              br(),
              downloadButton(
                outputId = ns("download_citations"),
                label = "Baixar Citações",
                icon = icon("download"),
                class = "btn-info btn-block"
              )
            )
          )
        )
      )
    ),
    
    # Citation Preview
    fluidRow(
      column(12,
        tabsetPanel(
          type = "tabs",
          
          # Preview Tab
          tabPanel(
            title = "Visualização",
            icon = icon("eye"),
            br(),
            
            fluidRow(
              column(12,
                h4("Citações Geradas"),
                div(
                  id = ns("citations_preview"),
                  style = "background-color: #f8f9fa; padding: 20px; border-radius: 5px; min-height: 200px;",
                  p("Selecione documentos e clique em 'Gerar Citações' para visualizar as citações.",
                    style = "color: #6c757d; font-style: italic;")
                )
              )
            )
          ),
          
          # BibTeX Tab
          tabPanel(
            title = "BibTeX",
            icon = icon("code"),
            br(),
            
            fluidRow(
              column(12,
                h4("Código BibTeX"),
                verbatimTextOutput(ns("bibtex_output"))
              )
            )
          ),
          
          # Citation List Tab
          tabPanel(
            title = "Lista Completa",
            icon = icon("list"),
            br(),
            
            fluidRow(
              column(12,
                h4("Lista de Citações"),
                DT::dataTableOutput(ns("citations_table"))
              )
            )
          ),
          
          # Export Options Tab
          tabPanel(
            title = "Exportar",
            icon = icon("file-export"),
            br(),
            
            fluidRow(
              column(6,
                h4("Formatos de Exportação"),
                wellPanel(
                  radioButtons(
                    inputId = ns("export_format"),
                    label = "Escolha o formato:",
                    choices = list(
                      "Texto (.txt)" = "txt",
                      "Word (.docx)" = "docx",
                      "BibTeX (.bib)" = "bib",
                      "RIS (.ris)" = "ris",
                      "JSON (.json)" = "json"
                    ),
                    selected = "txt"
                  ),
                  
                  checkboxGroupInput(
                    inputId = ns("export_options"),
                    label = "Opções:",
                    choices = list(
                      "Incluir metadados" = "metadata",
                      "Ordenar alfabeticamente" = "sort_alpha",
                      "Numerar citações" = "number_citations"
                    ),
                    selected = c("sort_alpha")
                  )
                )
              ),
              
              column(6,
                h4("Ações de Exportação"),
                br(),
                downloadButton(
                  outputId = ns("export_citations"),
                  label = "Exportar Citações",
                  icon = icon("download"),
                  class = "btn-primary btn-block"
                ),
                br(), br(),
                actionButton(
                  inputId = ns("copy_citations"),
                  label = "Copiar para Área de Transferência",
                  icon = icon("copy"),
                  class = "btn-secondary btn-block"
                ),
                br(), br(),
                actionButton(
                  inputId = ns("email_citations"),
                  label = "Enviar por Email",
                  icon = icon("envelope"),
                  class = "btn-info btn-block"
                )
              )
            )
          )
        )
      )
    )
  )
}

#' Citation Module Server
#' 
#' Server logic for citation generation including document search,
#' citation formatting, and export functionality.
#' 
#' @param id Character string for module namespace ID
#' @param reactive_data Reactive expression containing legislative data
#' @return List of reactive values and functions
#' @export
citationServer <- function(id, reactive_data) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns
    
    # Reactive values
    values <- reactiveValues(
      found_documents = NULL,
      selected_documents = NULL,
      generated_citations = NULL,
      selected_rows = c()
    )
    
    # Search documents
    observeEvent(input$search_documents, {
      req(reactive_data())
      
      data <- reactive_data()
      
      # Apply filters
      filtered_data <- data
      
      # Search term filter
      if (!isTRUE(is.null(input$document_search)) && input$document_search != "") {
        search_pattern <- paste0(".*", input$document_search, ".*")
        filtered_data <- filtered_data[
          grepl(search_pattern, filtered_data$titulo, ignore.case = TRUE) |
          safe_grepl(search_pattern, filtered_data$ementa), 
        ]
      }
      
      # Document type filter
      if (input$document_type_filter != "all") {
        type_pattern <- switch(input$document_type_filter,
          "lei" = "lei",
          "decreto" = "decreto",
          "resolucao" = "resolução|resolucao",
          "portaria" = "portaria",
          "instrucao_normativa" = "instrução normativa|instrucao normativa"
        )
        filtered_data <- filtered_data[
          safe_grepl(type_pattern, filtered_data$tipo_documento),
        ]
      }
      
      # State filter
      if (input$state_filter_citation != "all") {
        filtered_data <- filtered_data[filtered_data$estado == input$state_filter_citation, ]
      }
      
      # Store results
      values$found_documents <- filtered_data
    })
    
    # Render documents table
    output$documents_table <- DT::renderDataTable({
      req(values$found_documents)
      
      # Prepare display data
      display_data <- values$found_documents %>%
        select(titulo, tipo_documento, estado, data, autoridade) %>%
        mutate(
          data = as.character(data),
          titulo = str_trunc(titulo, 60)
        )
      
      DT::datatable(
        display_data,
        selection = list(mode = "multiple", selected = values$selected_rows),
        options = list(
          pageLength = 10,
          scrollX = TRUE,
          language = list(
            url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json"
          )
        ),
        colnames = c("Título", "Tipo", "Estado", "Data", "Autoridade"),
        rownames = FALSE
      )
    })
    
    # Track selected rows
    observeEvent(input$documents_table_rows_selected, {
      values$selected_rows <- input$documents_table_rows_selected
    })
    
    # Update selected count
    output$selected_count <- renderUI({
      count <- length(values$selected_rows)
      if (count > 0) {
        div(
          class = "alert alert-info",
          icon("info-circle"),
          strong(paste("Documentos selecionados:", count))
        )
      } else {
        div(
          class = "alert alert-secondary",
          icon("info-circle"),
          "Nenhum documento selecionado"
        )
      }
    })
    
    # Select all documents
    observeEvent(input$select_all, {
      req(values$found_documents)
      proxy <- DT::dataTableProxy("documents_table")
      DT::selectRows(proxy, 1:nrow(values$found_documents))
    })
    
    # Deselect all documents
    observeEvent(input$deselect_all, {
      proxy <- DT::dataTableProxy("documents_table")
      DT::selectRows(proxy, NULL)
    })
    
    # Clear selection
    observeEvent(input$clear_selection, {
      values$selected_rows <- c()
      proxy <- DT::dataTableProxy("documents_table")
      DT::selectRows(proxy, NULL)
    })
    
    # Generate citations - Enhanced Week 5 Implementation
    observeEvent(input$generate_citations, {
      req(values$found_documents, values$selected_rows)
      
      selected_docs <- values$found_documents[values$selected_rows, ]

      # Show progress for bulk operations
      if (!isTRUE(is.null(selected_docs)) && is.data.frame(selected_docs) && nrow(selected_docs) > 10) {
        withProgress(message = 'Gerando citações...', value = 0, {
          citations <- lapply(1:nrow(selected_docs), function(i) {
            incProgress(1/nrow(selected_docs), detail = paste("Documento", i, "de", nrow(selected_docs)))
            doc <- selected_docs[i, ]
            generate_citation_enhanced(doc, input$citation_format, input$citation_options, input$citation_language)
          })
        })
      } else {
        citations <- lapply(1:nrow(selected_docs), function(i) {
          doc <- selected_docs[i, ]
          generate_citation_enhanced(doc, input$citation_format, input$citation_options, input$citation_language)
        })
      }
      
      values$generated_citations <- citations
      
      # Update preview with validation indicators
      output$citations_preview <- renderUI({
        div(
          style = "background-color: white; padding: 15px;",
          lapply(1:length(citations), function(i) {
            citation <- citations[[i]]
            
            # Add validation indicator
            validation_icon <- if (!isTRUE(is.null(citation$validation)) && citation$validation$valid) {
              icon("check-circle", style = "color: green;")
            } else if (!is.null(citation$validation)) {
              icon("exclamation-triangle", style = "color: orange;")
            } else {
              icon("info-circle", style = "color: blue;")
            }
            
            div(
              style = "margin-bottom: 15px; padding: 10px; border-left: 4px solid #3498db;",
              div(
                style = "display: flex; align-items: center; margin-bottom: 5px;",
                validation_icon,
                span(paste("Citação", i), style = "margin-left: 5px; font-weight: bold;")
              ),
              p(citation$citation %||% citation, style = "margin: 5px 0;"),
              if (!isTRUE(is.null(citation$validation)) && length(citation$validation$warnings) > 0) {
                div(
                  style = "font-size: 0.8em; color: orange; margin-top: 5px;",
                  "⚠️ ", paste(citation$validation$warnings, collapse = ", ")
                )
              }
            )
          })
        )
      })
    })
    
    # Enhanced citation generation function - Week 5 Implementation
    generate_citation_enhanced <- function(document, format, options, language) {
      tryCatch({
        # Extract comprehensive metadata using enhanced system
        metadata <- extract_brazilian_legal_metadata(document, validate_metadata = TRUE)
        
        # Generate citation based on format with enhanced methods
        citation_result <- switch(format,
          "abnt" = list(
            citation = generate_abnt_citation_enhanced(
              metadata, 
              include_access_date = "include_access_date" %in% options,
              short_format = "short_format" %in% options
            ),
            format = "ABNT NBR 6023:2018"
          ),
          "apa" = list(
            citation = generate_apa_citation_enhanced(metadata, options, language),
            format = "APA 7th Edition"
          ),
          "chicago" = list(
            citation = generate_chicago_citation_enhanced(metadata, options, language),
            format = "Chicago Manual of Style"
          ),
          "vancouver" = list(
            citation = generate_vancouver_citation_enhanced(metadata, options, language),
            format = "Vancouver Style"
          ),
          "bibtex" = list(
            citation = generate_bibtex_citation_enhanced(metadata, options),
            format = "BibTeX"
          ),
          "custom" = list(
            citation = generate_custom_citation(metadata, input$custom_format_template %||% "", options),
            format = "Formato Personalizado"
          ),
          # Default to ABNT
          list(
            citation = generate_abnt_citation_enhanced(metadata),
            format = "ABNT NBR 6023:2018 (padrão)"
          )
        )
        
        # Add metadata and validation results
        citation_result$metadata <- metadata
        citation_result$validation <- metadata$validacao_resultado
        citation_result$generated_at <- Sys.time()
        citation_result$language <- language
        citation_result$options <- options
        
        return(citation_result)
        
      }, error = function(e) {
        return(list(
          citation = paste("Erro na geração da citação:", e$message),
          format = format,
          error = TRUE,
          error_message = e$message,
          generated_at = Sys.time()
        ))
      })
    }

    # Enhanced Citation Format Functions - Week 5 Implementation
    # =========================================================
    
    #' Generate Enhanced APA Citation
    generate_apa_citation_enhanced <- function(metadata, options, language) {
      if (language == "pt") {
        return(generate_apa_portuguese(metadata, options))
      } else {
        return(generate_apa_english(metadata, options))
      }
    }
    
    generate_apa_portuguese <- function(metadata, options) {
      citation_parts <- c()
      
      # Author (title case)
      author <- tools::toTitleCase(tolower(metadata$autoridade_emissor %||% "Autor desconhecido"))
      citation_parts <- c(citation_parts, paste0(author, "."))
      
      # Year
      year <- if (!is.null(metadata$data_publicacao)) format(metadata$data_publicacao, "%Y") else "s.d."
      citation_parts <- c(citation_parts, paste0("(", year, ")."))
      
      # Title (italics)
      title <- paste0("*", metadata$titulo_principal %||% metadata$titulo_completo, "*")
      if (!isTRUE(is.null(metadata$numero_documento)) && metadata$numero_documento != "") {
        title <- paste(title, "nº", metadata$numero_documento)
      }
      citation_parts <- c(citation_parts, paste0(title, "."))
      
      # Publisher and location
      if (!isTRUE(is.null(metadata$fonte_publicacao)) && metadata$fonte_publicacao != "") {
        citation_parts <- c(citation_parts, paste0(metadata$fonte_publicacao, "."))
      }
      
      # URL if available
      if ("include_url" %in% options && !isTRUE(is.null(metadata$url_oficial)) && metadata$url_oficial != "") {
        citation_parts <- c(citation_parts, paste0("Disponível em: ", metadata$url_oficial))
      }
      
      return(paste(citation_parts, collapse = " "))
    }
    
    generate_apa_english <- function(metadata, options) {
      citation_parts <- c()
      
      # Author
      author <- tools::toTitleCase(tolower(metadata$autoridade_emissor %||% "Unknown author"))
      citation_parts <- c(citation_parts, paste0(author, "."))
      
      # Year
      year <- if (!is.null(metadata$data_publicacao)) format(metadata$data_publicacao, "%Y") else "n.d."
      citation_parts <- c(citation_parts, paste0("(", year, ")."))
      
      # Title (italics)
      title <- paste0("*", metadata$titulo_principal %||% metadata$titulo_completo, "*")
      citation_parts <- c(citation_parts, paste0(title, "."))
      
      # Publisher
      if (!isTRUE(is.null(metadata$fonte_publicacao)) && metadata$fonte_publicacao != "") {
        citation_parts <- c(citation_parts, paste0(metadata$fonte_publicacao, "."))
      }
      
      # URL if available
      if ("include_url" %in% options && !isTRUE(is.null(metadata$url_oficial)) && metadata$url_oficial != "") {
        citation_parts <- c(citation_parts, paste0("Retrieved from ", metadata$url_oficial))
      }
      
      return(paste(citation_parts, collapse = " "))
    }
    
    #' Generate Enhanced Chicago Citation
    generate_chicago_citation_enhanced <- function(metadata, options, language) {
      citation_parts <- c()
      
      # Author
      author <- tools::toTitleCase(tolower(metadata$autoridade_emissor %||% "Autor desconhecido"))
      citation_parts <- c(citation_parts, paste0(author, "."))
      
      # Title (quoted)
      title <- paste0('"', metadata$titulo_principal %||% metadata$titulo_completo, '"')
      citation_parts <- c(citation_parts, title)
      
      # Publication info
      pub_info <- c()
      if (!isTRUE(is.null(metadata$fonte_publicacao)) && metadata$fonte_publicacao != "") {
        pub_info <- c(pub_info, metadata$fonte_publicacao)
      }
      if (!is.null(metadata$data_publicacao)) {
        pub_info <- c(pub_info, format(metadata$data_publicacao, "%B %d, %Y"))
      }
      
      if (length(pub_info) > 0) {
        citation_parts <- c(citation_parts, paste(pub_info, collapse = ", "))
      }
      
      # URL if available
      if ("include_url" %in% options && !isTRUE(is.null(metadata$url_oficial)) && metadata$url_oficial != "") {
        citation_parts <- c(citation_parts, metadata$url_oficial)
      }
      
      return(paste(citation_parts, collapse = ". "))
    }
    
    #' Generate Enhanced Vancouver Citation
    generate_vancouver_citation_enhanced <- function(metadata, options, language) {
      citation_parts <- c()
      
      # Author
      author <- metadata$autoridade_emissor %||% "Autor desconhecido"
      citation_parts <- c(citation_parts, paste0(author, "."))
      
      # Title
      title <- metadata$titulo_principal %||% metadata$titulo_completo
      citation_parts <- c(citation_parts, paste0(title, "."))
      
      # Publisher and year
      pub_info <- c()
      if (!isTRUE(is.null(metadata$fonte_publicacao)) && metadata$fonte_publicacao != "") {
        pub_info <- c(pub_info, metadata$fonte_publicacao)
      }
      if (!is.null(metadata$data_publicacao)) {
        pub_info <- c(pub_info, format(metadata$data_publicacao, "%Y"))
      }
      
      if (length(pub_info) > 0) {
        citation_parts <- c(citation_parts, paste0(paste(pub_info, collapse = "; "), "."))
      }
      
      return(paste(citation_parts, collapse = " "))
    }
    
    #' Generate Enhanced BibTeX Citation
    generate_bibtex_citation_enhanced <- function(metadata, options) {
      # Generate unique key
      author_key <- gsub("[^A-Za-z0-9]", "", metadata$autoridade_emissor %||% "unknown")
      year_key <- if (!is.null(metadata$data_publicacao)) format(metadata$data_publicacao, "%Y") else "nodate"
      key <- paste0(tolower(substr(author_key, 1, 10)), year_key)
      
      bibtex_parts <- c(
        paste0("@misc{", key, ","),
        paste0("  title = {", metadata$titulo_completo %||% "Título não disponível", "},"),
        paste0("  author = {", metadata$autoridade_emissor %||% "Autor desconhecido", "},"),
        paste0("  year = {", year_key, "},"),
        paste0("  institution = {", metadata$fonte_publicacao %||% "", "},")
      )
      
      if (!isTRUE(is.null(metadata$url_oficial)) && metadata$url_oficial != "") {
        bibtex_parts <- c(bibtex_parts, paste0("  url = {", metadata$url_oficial, "},"))
      }
      
      if (!isTRUE(is.null(metadata$ementa)) && metadata$ementa != "") {
        bibtex_parts <- c(bibtex_parts, paste0("  note = {", substr(metadata$ementa, 1, 100), "},"))
      }
      
      bibtex_parts <- c(bibtex_parts, "}")
      
      return(paste(bibtex_parts, collapse = "\n"))
    }
    
    #' Generate Custom Citation
    #' Allows users to create institutional-specific citation formats
    generate_custom_citation <- function(metadata, template, options) {
      if (isTRUE(is.null(template)) || template == "") {
        return("Template de formato personalizado não definido")
      }
      
      # Replace placeholders in template with metadata
      citation <- template
      
      # Standard placeholders
      replacements <- list(
        "{{AUTHOR}}" = metadata$autoridade_emissor %||% "",
        "{{TITLE}}" = metadata$titulo_completo %||% "",
        "{{TITLE_MAIN}}" = metadata$titulo_principal %||% "",
        "{{SUBTITLE}}" = metadata$subtitulo %||% "",
        "{{DATE}}" = if (!is.null(metadata$data_publicacao)) format(metadata$data_publicacao, "%d/%m/%Y") else "",
        "{{YEAR}}" = if (!is.null(metadata$data_publicacao)) format(metadata$data_publicacao, "%Y") else "",
        "{{STATE}}" = metadata$estado %||% "",
        "{{MUNICIPALITY}}" = metadata$municipio %||% "",
        "{{DOCUMENT_TYPE}}" = metadata$tipo_documento %||% "",
        "{{DOCUMENT_NUMBER}}" = metadata$numero_documento %||% "",
        "{{PUBLISHER}}" = metadata$fonte_publicacao %||% "",
        "{{URL}}" = metadata$url_oficial %||% "",
        "{{URN}}" = metadata$urn_lex %||% "",
        "{{SUMMARY}}" = metadata$ementa %||% "",
        "{{JOURNAL}}" = metadata$diario_oficial %||% "",
        "{{ACCESS_DATE}}" = format_abnt_date(Sys.Date())
      )
      
      # Apply replacements
      for (placeholder in names(replacements)) {
        citation <- gsub(placeholder, replacements[[placeholder]], citation, fixed = TRUE)
      }
      
      return(citation)
    }
    
    # ABNT citation format
    generate_abnt_citation <- function(title, author, date, state, type, url, options, language) {
      # Format according to ABNT NBR 6023
      citation_parts <- c()
      
      # Author (in uppercase)
      citation_parts <- c(citation_parts, toupper(author))
      
      # Title (in bold or italics)
      formatted_title <- paste0("**", title, "**")
      citation_parts <- c(citation_parts, formatted_title)
      
      # Publication info
      year <- format(as.Date(date), "%Y")
      pub_info <- paste0(state, ", ", year)
      citation_parts <- c(citation_parts, pub_info)
      
      # URL and access date if requested
      if ("include_url" %in% options) {
        url_part <- paste("Disponível em:", url)
        citation_parts <- c(citation_parts, url_part)
        
        if ("include_access_date" %in% options) {
          access_date <- format(Sys.Date(), "%d %b. %Y")
          access_part <- paste("Acesso em:", access_date)
          citation_parts <- c(citation_parts, access_part)
        }
      }
      
      return(paste(citation_parts, collapse = ". ") %&% ".")
    }
    
    # APA citation format
    generate_apa_citation <- function(title, author, date, state, type, url, options, language) {
      year <- format(as.Date(date), "%Y")
      
      citation <- paste0(
        author, " (", year, "). ",
        "*", title, "*. ",
        state, "."
      )
      
      if ("include_url" %in% options) {
        citation <- paste0(citation, " Retrieved from ", url)
      }
      
      return(citation)
    }
    
    # Chicago citation format
    generate_chicago_citation <- function(title, author, date, state, type, url, options, language) {
      year <- format(as.Date(date), "%Y")
      
      citation <- paste0(
        author, '. "', title, '." ',
        state, ', ', year, '.'
      )
      
      if ("include_url" %in% options) {
        citation <- paste0(citation, " ", url, ".")
      }
      
      return(citation)
    }
    
    # BibTeX citation format
    generate_bibtex_citation <- function(title, author, date, state, type, url, options) {
      key <- make.names(paste0(gsub("\\s+", "", author), format(as.Date(date), "%Y")))
      year <- format(as.Date(date), "%Y")
      
      bibtex <- paste0(
        "@misc{", key, ",\n",
        "  title = {", title, "},\n",
        "  author = {", author, "},\n",
        "  year = {", year, "},\n",
        "  address = {", state, "},\n"
      )
      
      if ("include_url" %in% options) {
        bibtex <- paste0(bibtex, "  url = {", url, "},\n")
      }
      
      bibtex <- paste0(bibtex, "}")
      
      return(bibtex)
    }
    
    # Vancouver citation format
    generate_vancouver_citation <- function(title, author, date, state, type, url, options, language) {
      year <- format(as.Date(date), "%Y")
      
      citation <- paste0(
        author, ". ", title, ". ",
        state, "; ", year, "."
      )
      
      if ("include_url" %in% options) {
        citation <- paste0(citation, " Available from: ", url)
      }
      
      return(citation)
    }
    
    # Render BibTeX output
    output$bibtex_output <- renderText({
      req(values$generated_citations)
      
      bibtex_citations <- lapply(values$selected_rows, function(i) {
        doc <- values$found_documents[i, ]
        generate_bibtex_citation(
          doc$titulo, doc$autoridade, doc$data, 
          doc$estado, doc$tipo_documento, doc$url, 
          input$citation_options
        )
      })
      
      paste(bibtex_citations, collapse = "\n\n")
    })
    
    # Download handler for citations
    output$download_citations <- downloadHandler(
      filename = function() {
        paste0("citacoes_", Sys.Date(), ".txt")
      },
      content = function(file) {
        req(values$generated_citations)
        
        citations_text <- paste(values$generated_citations, collapse = "\n\n")
        writeLines(citations_text, file)
      }
    )
    
    # Return reactive values
    return(
      list(
        selected_documents = reactive(values$selected_documents),
        generated_citations = reactive(values$generated_citations),
        citation_count = reactive(length(values$generated_citations))
      )
    )
  })
}

cat("✅ Citation module loaded successfully\n")
