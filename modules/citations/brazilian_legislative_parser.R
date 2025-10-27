# BRAZILIAN LEGISLATIVE METADATA PARSER - CIT-001
# ================================================
# Parse Brazilian legislative document metadata for academic citation generation
# Handles all Brazilian document types with proper URN integration
# 
# Features:
# - Brazilian legislative document type recognition
# - Authority and jurisdiction extraction
# - URN (Uniform Resource Name) parsing
# - Publication date standardization
# - Federal, State, Municipal level parsing
# - Committee and rapporteur extraction

cat("Loading Brazilian Legislative Metadata Parser...\n")

# Brazilian Legislative Document Type Classifications
BRAZILIAN_DOCUMENT_TYPES <- list(
  # Federal Level - Primary Legislation
  "Lei Federal" = list(
    pattern = "(?i)lei\\s+federal\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal",
    type_abbrev = "Lei Fed.",
    urn_pattern = "lex:br:federal:lei",
    weight = 1.0
  ),
  
  "Lei Ordinária" = list(
    pattern = "(?i)lei\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal", 
    type_abbrev = "Lei",
    urn_pattern = "lex:br:federal:lei",
    weight = 0.9
  ),
  
  "Lei Complementar" = list(
    pattern = "(?i)lei\\s+complementar\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal",
    type_abbrev = "Lei Compl.",
    urn_pattern = "lex:br:federal:lei.complementar",
    weight = 1.0
  ),
  
  # Federal Level - Executive Acts
  "Decreto Federal" = list(
    pattern = "(?i)decreto\\s+(?:federal\\s+)?n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal",
    type_abbrev = "Dec.",
    urn_pattern = "lex:br:federal:decreto",
    weight = 0.8
  ),
  
  "Medida Provisória" = list(
    pattern = "(?i)medida\\s+provisória\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal", 
    type_abbrev = "MP",
    urn_pattern = "lex:br:federal:medida.provisoria",
    weight = 0.8
  ),
  
  # Federal Level - Regulatory
  "Portaria Ministerial" = list(
    pattern = "(?i)portaria\\s+(?:ministerial\\s+)?n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal",
    type_abbrev = "Port.",
    urn_pattern = "lex:br:federal:portaria",
    weight = 0.6
  ),
  
  "Instrução Normativa" = list(
    pattern = "(?i)instrução\\s+normativa\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal",
    type_abbrev = "IN",
    urn_pattern = "lex:br:federal:instrucao.normativa",
    weight = 0.6
  ),
  
  # Regulatory Agency Resolutions
  "Resolução ANTT" = list(
    pattern = "(?i)resolução\\s+antt\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "ANTT",
    jurisdiction = "Federal",
    type_abbrev = "Res. ANTT",
    urn_pattern = "lex:br:federal:agencia.nacional.transportes.terrestres:resolucao",
    weight = 0.7
  ),
  
  "Resolução CONTRAN" = list(
    pattern = "(?i)resolução\\s+contran\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "CONTRAN",
    jurisdiction = "Federal",
    type_abbrev = "Res. CONTRAN",
    urn_pattern = "lex:br:federal:conselho.nacional.transito:resolucao",
    weight = 0.7
  ),
  
  "Resolução ANP" = list(
    pattern = "(?i)resolução\\s+anp\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "ANP",
    jurisdiction = "Federal",
    type_abbrev = "Res. ANP",
    urn_pattern = "lex:br:federal:agencia.nacional.petroleo:resolucao",
    weight = 0.7
  ),
  
  # State Level
  "Lei Estadual" = list(
    pattern = "(?i)lei\\s+estadual\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "ESTADO",
    jurisdiction = "Estadual",
    type_abbrev = "Lei Est.",
    urn_pattern = "lex:br:;estado;:lei",
    weight = 0.8
  ),
  
  "Decreto Estadual" = list(
    pattern = "(?i)decreto\\s+estadual\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "ESTADO", 
    jurisdiction = "Estadual",
    type_abbrev = "Dec. Est.",
    urn_pattern = "lex:br:;estado;:decreto",
    weight = 0.7
  ),
  
  # Municipal Level
  "Lei Municipal" = list(
    pattern = "(?i)lei\\s+municipal\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "MUNICÍPIO",
    jurisdiction = "Municipal", 
    type_abbrev = "Lei Mun.",
    urn_pattern = "lex:br:;municipio;:lei",
    weight = 0.7
  ),
  
  # Constitutional
  "Constituição Federal" = list(
    pattern = "(?i)constituição\\s+federal\\s*(?:de\\s+1988)?",
    authority = "BRASIL",
    jurisdiction = "Federal",
    type_abbrev = "CF/88",
    urn_pattern = "lex:br:federal:constituicao",
    weight = 1.0
  ),
  
  "Emenda Constitucional" = list(
    pattern = "(?i)emenda\\s+(?:à\\s+)?constituição\\s+n[ºo°\\.]*\\s*(\\d+(?:[\\./]\\d+)?)",
    authority = "BRASIL",
    jurisdiction = "Federal",
    type_abbrev = "EC",
    urn_pattern = "lex:br:federal:constituicao.emenda",
    weight = 1.0
  )
)

# Brazilian States for proper authority attribution
BRAZILIAN_STATES <- c(
  "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
  "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", "ES" = "Espírito Santo", 
  "GO" = "Goiás", "MA" = "Maranhão", "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul",
  "MG" = "Minas Gerais", "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná",
  "PE" = "Pernambuco", "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
  "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima", "SC" = "Santa Catarina",
  "SP" = "São Paulo", "SE" = "Sergipe", "TO" = "Tocantins"
)

#' Parse Brazilian Legislative Document Metadata
#' @param document_data Single document or data frame with document information
#' @param title_column Column name containing document title (default: "title")
#' @param state_column Column name containing state information (default: "state")
#' @param date_column Column name containing publication date (default: "date")
#' @param url_column Column name containing URL (default: "url")
#' @param urn_column Column name containing URN (default: "urn")
#' @return List with parsed metadata for citation generation
parse_brazilian_legislative_metadata <- function(document_data, 
                                                title_column = "title",
                                                state_column = "state", 
                                                date_column = "date",
                                                url_column = "url",
                                                urn_column = "urn") {
  
  if (!requireNamespace("stringr", quietly = TRUE)) {
    stop("stringr package required for Brazilian legislative parsing")
  }
  
  # Handle both single document and data frame inputs
  if (is.data.frame(document_data)) {
    # Process multiple documents
    results <- list()
    for (i in 1:nrow(document_data)) {
      doc_row <- document_data[i, , drop = FALSE]
      results[[i]] <- parse_single_document(doc_row, title_column, state_column, 
                                          date_column, url_column, urn_column)
    }
    return(results)
  } else {
    # Process single document
    return(parse_single_document(document_data, title_column, state_column,
                                date_column, url_column, urn_column))
  }
}

#' Parse Single Brazilian Legislative Document
#' @param doc_data Single document data (list or single-row data frame)
#' @param title_col Column name for title
#' @param state_col Column name for state
#' @param date_col Column name for date
#' @param url_col Column name for URL
#' @param urn_col Column name for URN
#' @return List with parsed metadata
parse_single_document <- function(doc_data, title_col, state_col, date_col, url_col, urn_col) {
  
  # Extract basic information
  title <- get_column_value(doc_data, title_col)
  state <- get_column_value(doc_data, state_col)
  date_raw <- get_column_value(doc_data, date_col)
  url <- get_column_value(doc_data, url_col)
  urn <- get_column_value(doc_data, urn_col)
  
  # Initialize result structure
  parsed_metadata <- list(
    original_title = title,
    document_type = "Documento Legislativo",
    document_number = "",
    authority = "BRASIL",
    jurisdiction = "Federal", 
    state_name = "",
    state_abbrev = "",
    publication_date = "",
    year = "",
    url = url %||% "",
    urn = urn %||% "",
    committee = "",
    rapporteur = "",
    co_authors = "",
    diario_oficial = "",
    parsing_confidence = 0.0,
    citation_elements = list()
  )
  
  if (isTRUE(is.null(title)) || title == "" || isTRUE(is.na(title))) {
    parsed_metadata$parsing_confidence <- 0.0
    return(parsed_metadata)
  }
  
  # Parse document type and number
  doc_type_result <- parse_document_type(title)
  parsed_metadata$document_type <- doc_type_result$type
  parsed_metadata$document_number <- doc_type_result$number
  parsed_metadata$authority <- doc_type_result$authority
  parsed_metadata$jurisdiction <- doc_type_result$jurisdiction
  parsed_metadata$parsing_confidence <- doc_type_result$confidence
  
  # Parse state information
  if (!isTRUE(is.null(state)) && state != "" && !is.na(state)) {
    state_result <- parse_state_info(state)
    parsed_metadata$state_name <- state_result$name
    parsed_metadata$state_abbrev <- state_result$abbrev
    
    # Update authority for state/municipal documents
    if (parsed_metadata$jurisdiction == "Estadual") {
      parsed_metadata$authority <- paste("ESTADO DE", state_result$name)
    } else if (parsed_metadata$jurisdiction == "Municipal") {
      # Try to extract municipality from title or other fields
      municipality <- extract_municipality_from_title(title)
      if (municipality != "") {
        parsed_metadata$authority <- paste("MUNICÍPIO DE", municipality)
      } else {
        parsed_metadata$authority <- paste("MUNICÍPIO (", state_result$abbrev, ")", sep="")
      }
    }
  }
  
  # Parse publication date
  if (!isTRUE(is.null(date_raw)) && date_raw != "" && !is.na(date_raw)) {
    date_result <- parse_publication_date(date_raw)
    parsed_metadata$publication_date <- date_result$formatted_date
    parsed_metadata$year <- date_result$year
  }
  
  # Parse URN if available
  if (!isTRUE(is.null(urn)) && urn != "" && !is.na(urn)) {
    urn_result <- parse_urn(urn)
    # Override with URN information if more reliable
    if (urn_result$confidence > parsed_metadata$parsing_confidence) {
      parsed_metadata$document_type <- urn_result$type %||% parsed_metadata$document_type
      parsed_metadata$authority <- urn_result$authority %||% parsed_metadata$authority
      parsed_metadata$jurisdiction <- urn_result$jurisdiction %||% parsed_metadata$jurisdiction
    }
  }
  
  # Extract additional metadata from title
  additional_metadata <- extract_additional_metadata(title)
  parsed_metadata$committee <- additional_metadata$committee
  parsed_metadata$rapporteur <- additional_metadata$rapporteur
  parsed_metadata$co_authors <- additional_metadata$co_authors
  parsed_metadata$diario_oficial <- additional_metadata$diario_oficial
  
  # Build citation elements for different formats
  parsed_metadata$citation_elements <- build_citation_elements(parsed_metadata)
  
  return(parsed_metadata)
}

#' Parse Document Type from Title
#' @param title Document title
#' @return List with type, number, authority, jurisdiction, confidence
parse_document_type <- function(title) {
  result <- list(
    type = "Documento Legislativo",
    number = "",
    authority = "BRASIL",
    jurisdiction = "Federal",
    confidence = 0.0
  )
  
  if (isTRUE(is.null(title)) || title == "") return(result)
  
  # Try each document type pattern
  for (type_name in names(BRAZILIAN_DOCUMENT_TYPES)) {
    pattern_info <- BRAZILIAN_DOCUMENT_TYPES[[type_name]]
    
    if (grepl(pattern_info$pattern, title, perl = TRUE)) {
      result$type <- type_name
      result$authority <- pattern_info$authority
      result$jurisdiction <- pattern_info$jurisdiction
      result$confidence <- pattern_info$weight
      
      # Extract document number
      number_match <- stringr::str_match(title, pattern_info$pattern)
      if (!is.na(number_match[2])) {
        result$number <- number_match[2]
      }
      
      break
    }
  }
  
  # Special handling for constitutional references
  if (grepl("(?i)(art\\.?\\s*\\d+|artigo\\s+\\d+).*?constituição", title, perl = TRUE)) {
    result$type <- "Constituição Federal"
    result$authority <- "BRASIL"
    result$jurisdiction <- "Federal"
    result$confidence <- 1.0
  }
  
  return(result)
}

#' Parse State Information
#' @param state_input State string (abbreviation or full name)
#' @return List with name and abbreviation
parse_state_info <- function(state_input) {
  result <- list(name = "", abbrev = "")
  
  if (isTRUE(is.null(state_input)) || state_input == "") return(result)
  
  state_clean <- stringr::str_trim(toupper(state_input))
  
  # Check if it's an abbreviation
  if (state_clean %in% names(BRAZILIAN_STATES)) {
    result$abbrev <- state_clean
    result$name <- BRAZILIAN_STATES[[state_clean]]
  } else if (state_clean %in% BRAZILIAN_STATES) {
    # Check if it's a full name
    result$name <- state_clean
    result$abbrev <- names(BRAZILIAN_STATES)[BRAZILIAN_STATES == state_clean]
  } else {
    # Try partial matching
    matches <- grep(paste0("^", state_clean), BRAZILIAN_STATES, ignore.case = TRUE, value = TRUE)
    if (length(matches) > 0) {
      result$name <- matches[1]
      result$abbrev <- names(BRAZILIAN_STATES)[BRAZILIAN_STATES == matches[1]]
    }
  }
  
  return(result)
}

#' Parse Publication Date
#' @param date_input Date in various formats
#' @return List with formatted date and year
parse_publication_date <- function(date_input) {
  result <- list(formatted_date = "", year = "")
  
  if (isTRUE(is.null(date_input)) || date_input == "") return(result)
  
  tryCatch({
    # Try to parse as Date object first
    if (inherits(date_input, "Date")) {
      parsed_date <- date_input
    } else {
      # Try common Brazilian date formats
      date_formats <- c("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d")
      parsed_date <- NULL
      
      for (fmt in date_formats) {
        tryCatch({
          parsed_date <- as.Date(date_input, format = fmt)
          if (!is.na(parsed_date)) break
        }, error = function(e) NULL)
      }
      
      # If still not parsed, try with lubridate if available
      if (isTRUE(is.null(parsed_date)) && requireNamespace("lubridate", quietly = TRUE)) {
        tryCatch({
          parsed_date <- lubridate::ymd(date_input)
          if (is.na(parsed_date)) {
            parsed_date <- lubridate::dmy(date_input)
          }
        }, error = function(e) NULL)
      }
    }
    
    if (!isTRUE(is.null(parsed_date)) && !is.na(parsed_date)) {
      # Format for Brazilian academic citations
      result$formatted_date <- format(parsed_date, "%d de %B de %Y")
      result$year <- format(parsed_date, "%Y")
      
      # Convert month names to Portuguese
      result$formatted_date <- portuguese_date_format(parsed_date)
    }
    
  }, error = function(e) {
    # Extract year if possible
    year_match <- stringr::str_extract(as.character(date_input), "\\d{4}")
    if (!is.na(year_match)) {
      result$year <- year_match
    }
  })
  
  return(result)
}

#' Format Date in Portuguese
#' @param date_obj Date object
#' @return Formatted Portuguese date string
portuguese_date_format <- function(date_obj) {
  if (isTRUE(is.null(date_obj)) || isTRUE(is.na(date_obj))) return("")
  
  month_names <- c(
    "janeiro", "fevereiro", "março", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"
  )
  
  day <- format(date_obj, "%d")
  month_num <- as.numeric(format(date_obj, "%m"))
  year <- format(date_obj, "%Y")
  
  # Remove leading zero from day
  day <- as.numeric(day)
  
  return(paste(day, "de", month_names[month_num], "de", year))
}

#' Parse URN (Uniform Resource Name) for Brazilian Legislation
#' @param urn_string URN string
#' @return List with parsed URN components
parse_urn <- function(urn_string) {
  result <- list(
    type = NULL,
    authority = NULL,
    jurisdiction = NULL,
    confidence = 0.0
  )
  
  if (isTRUE(is.null(urn_string)) || urn_string == "") return(result)
  
  # Brazilian LexML URN pattern: lex:br:federal:lei:1988-10-05;9394
  if (grepl("^lex:br:", urn_string)) {
    result$confidence <- 0.9
    
    # Extract jurisdiction
    if (grepl(":federal:", urn_string)) {
      result$jurisdiction <- "Federal"
      result$authority <- "BRASIL"
    } else if (grepl(":estadual:", urn_string)) {
      result$jurisdiction <- "Estadual" 
      result$authority <- "ESTADO"
    } else if (grepl(":municipal:", urn_string)) {
      result$jurisdiction <- "Municipal"
      result$authority <- "MUNICÍPIO"
    }
    
    # Extract document type
    if (grepl(":lei:", urn_string)) {
      result$type <- "Lei Federal"
    } else if (grepl(":decreto:", urn_string)) {
      result$type <- "Decreto Federal"
    } else if (grepl(":constituicao:", urn_string)) {
      result$type <- "Constituição Federal"
    } else if (grepl(":resolucao:", urn_string)) {
      result$type <- "Resolução"
    }
  }
  
  return(result)
}

#' Extract Municipality from Title
#' @param title Document title
#' @return Municipality name or empty string
extract_municipality_from_title <- function(title) {
  if (isTRUE(is.null(title)) || title == "") return("")
  
  # Common patterns for municipalities in Brazilian legislation
  municipality_patterns <- c(
    "(?i)município\\s+de\\s+([a-záàâãçéêíóôõúû\\s]+)",
    "(?i)prefeitura\\s+de\\s+([a-záàâãçéêíóôõúû\\s]+)",
    "(?i)câmara\\s+municipal\\s+de\\s+([a-záàâãçéêíóôõúû\\s]+)"
  )
  
  for (pattern in municipality_patterns) {
    match <- stringr::str_match(title, pattern)
    if (!is.na(match[2])) {
      return(stringr::str_trim(stringr::str_to_title(match[2])))
    }
  }
  
  return("")
}

#' Extract Additional Metadata from Title
#' @param title Document title
#' @return List with additional metadata elements
extract_additional_metadata <- function(title) {
  result <- list(
    committee = "",
    rapporteur = "",
    co_authors = "",
    diario_oficial = ""
  )
  
  if (isTRUE(is.null(title)) || title == "") return(result)
  
  # Extract committee information
  committee_match <- stringr::str_match(title, "(?i)comissão\\s+([a-záàâãçéêíóôõúû\\s]+)")
  if (!is.na(committee_match[2])) {
    result$committee <- stringr::str_trim(committee_match[2])
  }
  
  # Extract rapporteur information
  rapporteur_match <- stringr::str_match(title, "(?i)relator[a]?:?\\s+([a-záàâãçéêíóôõúû\\s]+)")
  if (!is.na(rapporteur_match[2])) {
    result$rapporteur <- stringr::str_trim(rapporteur_match[2])
  }
  
  # Extract Diário Oficial reference
  do_match <- stringr::str_match(title, "(?i)d\\.?o\\.?u?\\s*([0-9\\-/]+)")
  if (!is.na(do_match[2])) {
    result$diario_oficial <- stringr::str_trim(do_match[2])
  }
  
  return(result)
}

#' Build Citation Elements for Different Formats
#' @param parsed_metadata Parsed metadata list
#' @return List with citation elements for different citation styles
build_citation_elements <- function(parsed_metadata) {
  elements <- list(
    abnt = list(),
    apa = list(),
    vancouver = list(),
    bluebook = list()
  )
  
  # ABNT Elements (Brazilian Standard)
  elements$abnt <- list(
    author_entry = parsed_metadata$authority,
    title = parsed_metadata$original_title,
    document_type = parsed_metadata$document_type,
    number = parsed_metadata$document_number,
    date = parsed_metadata$publication_date,
    year = parsed_metadata$year,
    url = parsed_metadata$url,
    access_date = format(Sys.Date(), "%d %b. %Y")
  )
  
  # APA Elements (International)
  elements$apa <- list(
    author = parsed_metadata$authority,
    year = paste0("(", parsed_metadata$year, ")"),
    title = paste0(parsed_metadata$document_type, " ", parsed_metadata$document_number),
    publisher = "Diário Oficial",
    url = parsed_metadata$url
  )
  
  # Vancouver Elements (Medical/Scientific)
  elements$vancouver <- list(
    author = parsed_metadata$authority,
    title = parsed_metadata$original_title,
    source = parsed_metadata$document_type,
    year = parsed_metadata$year,
    url = parsed_metadata$url
  )
  
  # Bluebook Elements (Legal)
  elements$bluebook <- list(
    title = paste0(parsed_metadata$document_type, " ", parsed_metadata$document_number),
    jurisdiction = parsed_metadata$jurisdiction,
    year = parsed_metadata$year,
    url = parsed_metadata$url
  )
  
  return(elements)
}

# Utility Functions
get_column_value <- function(data, column_name) {
  if (is.data.frame(data)) {
    if (column_name %in% names(data)) {
      value <- data[[column_name]][1]
      return(if (is.na(value)) "" else as.character(value))
    }
  } else if (is.list(data)) {
    if (column_name %in% names(data)) {
      value <- data[[column_name]]
      return(if (is.na(value)) "" else as.character(value))
    }
  }
  return("")
}

`%||%` <- function(a, b) if (isTRUE(is.null(a)) || isTRUE(is.na(a)) || a == "") b else a

#' Test Brazilian Legislative Parser
#' @return Test results
test_brazilian_parser <- function() {
  cat("Testing Brazilian Legislative Metadata Parser...\n")
  
  # Test documents
  test_docs <- data.frame(
    title = c(
      "Lei Federal nº 14.133/2021 - Nova Lei de Licitações",
      "Decreto nº 10.881/2021 - Governo Digital",
      "Resolução ANTT nº 5.232/2020 - RNTRC",
      "Lei Complementar nº 182/2021 - Marco das Startups",
      "Constituição Federal de 1988"
    ),
    state = c("DF", "DF", "DF", "DF", "DF"),
    date = c("2021-04-01", "2021-06-15", "2020-12-10", "2021-06-27", "1988-10-05"),
    url = c("", "", "", "", ""),
    urn = c("", "", "", "", ""),
    stringsAsFactors = FALSE
  )
  
  # Parse all documents
  results <- parse_brazilian_legislative_metadata(test_docs)
  
  # Display results
  for (i in seq_along(results)) {
    cat("\n--- Document", i, "---\n")
    cat("Type:", results[[i]]$document_type, "\n")
    cat("Number:", results[[i]]$document_number, "\n") 
    cat("Authority:", results[[i]]$authority, "\n")
    cat("Jurisdiction:", results[[i]]$jurisdiction, "\n")
    cat("Date:", results[[i]]$publication_date, "\n")
    cat("Confidence:", results[[i]]$parsing_confidence, "\n")
  }
  
  cat("\n✅ Brazilian Legislative Parser test completed\n")
  return(results)
}

cat("✅ Brazilian Legislative Metadata Parser loaded successfully\n")
cat("   📚 Brazilian document types: ", length(BRAZILIAN_DOCUMENT_TYPES), "\n")
cat("   🏛️ Jurisdictions supported: Federal, Estadual, Municipal\n")
cat("   🏷️ URN parsing: ENABLED\n")
cat("   📅 Portuguese date formatting: ENABLED\n")
cat("   ⚖️ Legal authority extraction: ENABLED\n")

# Export main functions
BRAZILIAN_PARSER_FUNCTIONS <- list(
  parse_brazilian_legislative_metadata = parse_brazilian_legislative_metadata,
  parse_document_type = parse_document_type,
  parse_state_info = parse_state_info,
  parse_publication_date = parse_publication_date,
  parse_urn = parse_urn,
  test_brazilian_parser = test_brazilian_parser
)