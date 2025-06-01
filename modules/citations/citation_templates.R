# BRAZILIAN CITATION FORMAT TEMPLATES - CIT-002
# ==============================================
# Academic citation templates for Brazilian legislative documents
# Priority: ABNT NBR 6023:2018 (Brazilian Standard)
# Also supports: APA 7th Edition, Vancouver, Bluebook
# 
# Features:
# - ABNT NBR 6023:2018 compliance for Brazilian academic work
# - APA 7th Edition for international publications
# - Vancouver style for medical/scientific journals
# - Bluebook format for legal citations
# - Portuguese and English language support
# - Proper handling of Brazilian government authorities

cat("Loading Brazilian Citation Format Templates...\n")

# ABNT NBR 6023:2018 TEMPLATES (PRIORITY)
# =======================================

#' Generate ABNT Citation for Brazilian Legislative Documents
#' Following NBR 6023:2018 standard
#' @param parsed_metadata Parsed metadata from brazilian_legislative_parser
#' @param language Language for citation ("pt" for Portuguese, "en" for English)
#' @return Formatted ABNT citation string
format_abnt_citation <- function(parsed_metadata, language = "pt") {
  if (is.null(parsed_metadata) || is.null(parsed_metadata$citation_elements)) {
    return("Erro: Metadados não disponíveis para citação ABNT")
  }
  
  elements <- parsed_metadata$citation_elements$abnt
  
  # ABNT Format for Laws: AUTHORITY. Document Type nº number, date. Publication info.
  citation_parts <- c()
  
  # 1. AUTHORITY (always uppercase in ABNT)
  if (!is.null(elements$author_entry) && elements$author_entry != "") {
    citation_parts <- c(citation_parts, toupper(elements$author_entry))
  }
  
  # 2. Document Type and Number
  doc_info <- ""
  if (!is.null(parsed_metadata$document_type) && parsed_metadata$document_type != "") {
    doc_info <- parsed_metadata$document_type
    
    if (!is.null(elements$number) && elements$number != "") {
      doc_info <- paste(doc_info, "nº", elements$number)
    }
  }
  
  if (doc_info != "") {
    citation_parts <- c(citation_parts, paste0(doc_info, ","))
  }
  
  # 3. Date (Brazilian format)
  if (!is.null(elements$date) && elements$date != "") {
    citation_parts <- c(citation_parts, paste0("de ", elements$date, "."))
  } else if (!is.null(elements$year) && elements$year != "") {
    citation_parts <- c(citation_parts, paste0(elements$year, "."))
  }
  
  # 4. Title (if different from document type)
  if (!is.null(parsed_metadata$original_title) && 
      parsed_metadata$original_title != "" &&
      !grepl(parsed_metadata$document_type, parsed_metadata$original_title, ignore.case = TRUE)) {
    title_clean <- clean_title_for_citation(parsed_metadata$original_title)
    citation_parts <- c(citation_parts, paste0(title_clean, "."))
  }
  
  # 5. Publication information (Diário Oficial)
  if (language == "pt") {
    pub_info <- "Diário Oficial da União"
  } else {
    pub_info <- "Official Gazette"
  }
  
  if (!is.null(parsed_metadata$diario_oficial) && parsed_metadata$diario_oficial != "") {
    pub_info <- paste(pub_info, parsed_metadata$diario_oficial)
  }
  citation_parts <- c(citation_parts, paste0(pub_info, "."))
  
  # 6. URL and access date (if available)
  if (!is.null(elements$url) && elements$url != "") {
    if (language == "pt") {
      url_part <- paste0("Disponível em: ", elements$url, ". Acesso em: ", elements$access_date, ".")
    } else {
      url_part <- paste0("Available at: ", elements$url, ". Accessed: ", elements$access_date, ".")
    }
    citation_parts <- c(citation_parts, url_part)
  }
  
  # Join all parts
  return(paste(citation_parts, collapse = " "))
}

#' Generate ABNT Bibliography Entry
#' @param parsed_metadata_list List of parsed metadata objects
#' @param language Language for bibliography
#' @return Formatted ABNT bibliography
format_abnt_bibliography <- function(parsed_metadata_list, language = "pt") {
  if (!is.list(parsed_metadata_list)) {
    parsed_metadata_list <- list(parsed_metadata_list)
  }
  
  bibliography <- c()
  
  if (language == "pt") {
    bibliography <- c(bibliography, "REFERÊNCIAS")
  } else {
    bibliography <- c(bibliography, "REFERENCES")
  }
  
  bibliography <- c(bibliography, "")  # Empty line
  
  # Sort by author/authority (ABNT requirement)
  citations <- sapply(parsed_metadata_list, function(meta) {
    format_abnt_citation(meta, language)
  })
  
  citations_sorted <- sort(citations)
  bibliography <- c(bibliography, citations_sorted)
  
  return(paste(bibliography, collapse = "\n"))
}

# APA 7TH EDITION TEMPLATES
# =========================

#' Generate APA 7th Edition Citation
#' @param parsed_metadata Parsed metadata
#' @param language Language for citation
#' @return Formatted APA citation string
format_apa_citation <- function(parsed_metadata, language = "en") {
  if (is.null(parsed_metadata) || is.null(parsed_metadata$citation_elements)) {
    return("Error: Metadata not available for APA citation")
  }
  
  elements <- parsed_metadata$citation_elements$apa
  
  # APA Format: Author. (Year). Title. Publisher.
  citation_parts <- c()
  
  # 1. Author (Government agency)
  if (!is.null(elements$author) && elements$author != "") {
    # Convert to proper case for APA
    author_apa <- stringr::str_to_title(tolower(elements$author))
    citation_parts <- c(citation_parts, paste0(author_apa, "."))
  }
  
  # 2. Year
  if (!is.null(elements$year) && elements$year != "") {
    citation_parts <- c(citation_parts, paste0(elements$year, "."))
  }
  
  # 3. Title (italicized in APA)
  if (!is.null(elements$title) && elements$title != "") {
    title_clean <- clean_title_for_citation(parsed_metadata$original_title)
    citation_parts <- c(citation_parts, paste0("*", title_clean, "*."))
  }
  
  # 4. Publisher
  if (!is.null(elements$publisher) && elements$publisher != "") {
    citation_parts <- c(citation_parts, paste0(elements$publisher, "."))
  }
  
  # 5. URL (if available)
  if (!is.null(elements$url) && elements$url != "") {
    citation_parts <- c(citation_parts, elements$url)
  }
  
  return(paste(citation_parts, collapse = " "))
}

# VANCOUVER STYLE TEMPLATES
# =========================

#' Generate Vancouver Style Citation
#' @param parsed_metadata Parsed metadata
#' @param citation_number Citation number for numbered system
#' @return Formatted Vancouver citation string
format_vancouver_citation <- function(parsed_metadata, citation_number = 1) {
  if (is.null(parsed_metadata) || is.null(parsed_metadata$citation_elements)) {
    return("Error: Metadata not available for Vancouver citation")
  }
  
  elements <- parsed_metadata$citation_elements$vancouver
  
  # Vancouver Format: Number. Author. Title. Source; Year.
  citation_parts <- c()
  
  # 1. Number
  citation_parts <- c(citation_parts, paste0(citation_number, "."))
  
  # 2. Author
  if (!is.null(elements$author) && elements$author != "") {
    author_vancouver <- stringr::str_to_title(tolower(elements$author))
    citation_parts <- c(citation_parts, paste0(author_vancouver, "."))
  }
  
  # 3. Title
  if (!is.null(elements$title) && elements$title != "") {
    title_clean <- clean_title_for_citation(parsed_metadata$original_title)
    citation_parts <- c(citation_parts, paste0(title_clean, "."))
  }
  
  # 4. Source and Year
  source_info <- ""
  if (!is.null(elements$source) && elements$source != "") {
    source_info <- elements$source
  }
  if (!is.null(elements$year) && elements$year != "") {
    source_info <- paste(source_info, elements$year, sep = "; ")
  }
  
  if (source_info != "") {
    citation_parts <- c(citation_parts, paste0(source_info, "."))
  }
  
  # 5. URL (if available)
  if (!is.null(elements$url) && elements$url != "") {
    citation_parts <- c(citation_parts, paste0("Available from: ", elements$url))
  }
  
  return(paste(citation_parts, collapse = " "))
}

# BLUEBOOK TEMPLATES (LEGAL CITATIONS)
# ===================================

#' Generate Bluebook Legal Citation
#' @param parsed_metadata Parsed metadata
#' @return Formatted Bluebook citation string
format_bluebook_citation <- function(parsed_metadata) {
  if (is.null(parsed_metadata) || is.null(parsed_metadata$citation_elements)) {
    return("Error: Metadata not available for Bluebook citation")
  }
  
  elements <- parsed_metadata$citation_elements$bluebook
  
  # Bluebook Format varies by document type
  citation_parts <- c()
  
  # Brazilian Legislative Documents in Bluebook format
  if (!is.null(elements$title) && elements$title != "") {
    citation_parts <- c(citation_parts, elements$title)
  }
  
  if (!is.null(elements$jurisdiction) && elements$jurisdiction != "" &&
      !is.null(elements$year) && elements$year != "") {
    jurisdiction_year <- paste0("(", elements$jurisdiction, " ", elements$year, ")")
    citation_parts <- c(citation_parts, jurisdiction_year)
  }
  
  if (!is.null(elements$url) && elements$url != "") {
    citation_parts <- c(citation_parts, elements$url)
  }
  
  return(paste(citation_parts, collapse = ", "))
}

# SPECIALIZED CITATION FUNCTIONS
# ==============================

#' Generate Constitutional Citation (ABNT)
#' Special handling for constitutional references
#' @param article_number Article number
#' @param paragraph Paragraph number (optional)
#' @param language Language for citation
#' @return Formatted constitutional citation
format_constitutional_citation <- function(article_number, paragraph = NULL, language = "pt") {
  if (language == "pt") {
    citation <- "BRASIL. Constituição (1988). Constituição da República Federativa do Brasil. Brasília, DF: Senado Federal: Centro Gráfico, 1988."
    
    if (!is.null(article_number)) {
      article_ref <- paste0("art. ", article_number)
      if (!is.null(paragraph)) {
        article_ref <- paste0(article_ref, ", § ", paragraph)
      }
      citation <- paste(citation, article_ref, sep = ", ")
    }
  } else {
    citation <- "BRAZIL. Constitution (1988). Constitution of the Federative Republic of Brazil. Brasília, DF: Federal Senate, 1988."
    
    if (!is.null(article_number)) {
      article_ref <- paste0("art. ", article_number)
      if (!is.null(paragraph)) {
        article_ref <- paste0(article_ref, ", § ", paragraph)
      }
      citation <- paste(citation, article_ref, sep = ", ")
    }
  }
  
  return(paste0(citation, "."))
}

#' Generate State Law Citation (ABNT)
#' @param state_name Full state name
#' @param law_number Law number
#' @param year Year
#' @param title Law title (optional)
#' @param language Language for citation
#' @return Formatted state law citation
format_state_law_citation <- function(state_name, law_number, year, title = NULL, language = "pt") {
  authority <- paste("ESTADO DE", toupper(state_name))
  
  citation_parts <- c(authority)
  
  law_info <- paste("Lei nº", law_number)
  if (!is.null(year)) {
    law_info <- paste0(law_info, ", de ", year)
  }
  citation_parts <- c(citation_parts, paste0(law_info, "."))
  
  if (!is.null(title) && title != "") {
    title_clean <- clean_title_for_citation(title)
    citation_parts <- c(citation_parts, paste0(title_clean, "."))
  }
  
  if (language == "pt") {
    publication <- "Diário Oficial do Estado."
  } else {
    publication <- "State Official Gazette."
  }
  citation_parts <- c(citation_parts, publication)
  
  return(paste(citation_parts, collapse = " "))
}

#' Generate Municipal Law Citation (ABNT)
#' @param municipality Municipality name
#' @param state_abbrev State abbreviation
#' @param law_number Law number
#' @param year Year
#' @param title Law title (optional)
#' @param language Language for citation
#' @return Formatted municipal law citation
format_municipal_law_citation <- function(municipality, state_abbrev, law_number, year, title = NULL, language = "pt") {
  authority <- paste0("MUNICÍPIO DE ", toupper(municipality), " (", toupper(state_abbrev), ")")
  
  citation_parts <- c(authority)
  
  law_info <- paste("Lei nº", law_number)
  if (!is.null(year)) {
    law_info <- paste0(law_info, ", de ", year)
  }
  citation_parts <- c(citation_parts, paste0(law_info, "."))
  
  if (!is.null(title) && title != "") {
    title_clean <- clean_title_for_citation(title)
    citation_parts <- c(citation_parts, paste0(title_clean, "."))
  }
  
  if (language == "pt") {
    publication <- "Diário Oficial do Município."
  } else {
    publication <- "Municipal Official Gazette."
  }
  citation_parts <- c(citation_parts, publication)
  
  return(paste(citation_parts, collapse = " "))
}

# UTILITY FUNCTIONS
# ================

#' Clean Title for Citation
#' Remove excess whitespace and standardize formatting
#' @param title Original title
#' @return Cleaned title
clean_title_for_citation <- function(title) {
  if (is.null(title) || title == "") return("")
  
  # Remove extra whitespace
  title_clean <- stringr::str_squish(title)
  
  # Remove common prefixes that are redundant in citations
  title_clean <- stringr::str_remove(title_clean, "^(?i)(lei|decreto|resolução|portaria)\\s+(federal\\s+)?n[ºo°\\.]*\\s*\\d+[\\./]*\\d*\\s*[-–—]?\\s*")
  
  # Ensure first letter is capitalized
  title_clean <- stringr::str_to_sentence(title_clean)
  
  return(title_clean)
}

#' Generate Multiple Format Citations
#' @param parsed_metadata Parsed metadata
#' @param formats Vector of formats to generate
#' @param language Language for citations
#' @return List of citations in different formats
generate_multiple_citations <- function(parsed_metadata, formats = c("abnt", "apa", "vancouver", "bluebook"), language = "pt") {
  citations <- list()
  
  for (format in formats) {
    citations[[format]] <- switch(format,
      "abnt" = format_abnt_citation(parsed_metadata, language),
      "apa" = format_apa_citation(parsed_metadata, language),
      "vancouver" = format_vancouver_citation(parsed_metadata),
      "bluebook" = format_bluebook_citation(parsed_metadata),
      paste("Unsupported format:", format)
    )
  }
  
  return(citations)
}

#' Preview Citation Formats
#' @param parsed_metadata Parsed metadata
#' @return HTML formatted preview of all citation styles
preview_citation_formats <- function(parsed_metadata) {
  citations <- generate_multiple_citations(parsed_metadata)
  
  html_preview <- c(
    "<div class='citation-preview'>",
    "<h4>Prévia de Citações</h4>",
    "",
    "<div class='citation-format'>",
    "<h5>ABNT NBR 6023:2018</h5>",
    paste0("<p class='citation-text abnt'>", citations$abnt, "</p>"),
    "</div>",
    "",
    "<div class='citation-format'>", 
    "<h5>APA 7ª Edição</h5>",
    paste0("<p class='citation-text apa'>", citations$apa, "</p>"),
    "</div>",
    "",
    "<div class='citation-format'>",
    "<h5>Vancouver</h5>",
    paste0("<p class='citation-text vancouver'>", citations$vancouver, "</p>"),
    "</div>",
    "",
    "<div class='citation-format'>",
    "<h5>Bluebook</h5>",
    paste0("<p class='citation-text bluebook'>", citations$bluebook, "</p>"),
    "</div>",
    "",
    "</div>"
  )
  
  return(paste(html_preview, collapse = "\n"))
}

#' Test Citation Templates
#' @return Test results
test_citation_templates <- function() {
  cat("Testing Citation Format Templates...\n")
  
  # Load parser if not already loaded
  if (!exists("parse_brazilian_legislative_metadata")) {
    if (file.exists("modules/citations/brazilian_legislative_parser.R")) {
      source("modules/citations/brazilian_legislative_parser.R")
    }
  }
  
  # Test document
  test_doc <- data.frame(
    title = "Lei Federal nº 14.133/2021 - Nova Lei de Licitações e Contratos Administrativos",
    state = "DF",
    date = "2021-04-01",
    url = "http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/L14133.htm",
    urn = "lex:br:federal:lei:2021-04-01;14133",
    stringsAsFactors = FALSE
  )
  
  # Parse metadata
  if (exists("parse_brazilian_legislative_metadata")) {
    parsed <- parse_brazilian_legislative_metadata(test_doc)[[1]]
    
    # Generate citations
    abnt_citation <- format_abnt_citation(parsed, "pt")
    apa_citation <- format_apa_citation(parsed, "en")
    vancouver_citation <- format_vancouver_citation(parsed, 1)
    bluebook_citation <- format_bluebook_citation(parsed)
    
    cat("\n--- CITATION FORMAT TESTS ---\n")
    cat("\nABNT NBR 6023:2018:\n", abnt_citation, "\n")
    cat("\nAPA 7th Edition:\n", apa_citation, "\n")
    cat("\nVancouver:\n", vancouver_citation, "\n")
    cat("\nBluebook:\n", bluebook_citation, "\n")
    
    return(list(
      abnt = abnt_citation,
      apa = apa_citation,
      vancouver = vancouver_citation,
      bluebook = bluebook_citation
    ))
  } else {
    cat("⚠️ Brazilian parser not available for testing\n")
    return(NULL)
  }
}

cat("✅ Brazilian Citation Format Templates loaded successfully\n")
cat("   📖 ABNT NBR 6023:2018: ENABLED (Priority)\n")
cat("   🌍 APA 7th Edition: ENABLED\n")
cat("   🔬 Vancouver Style: ENABLED\n")
cat("   ⚖️ Bluebook Format: ENABLED\n")
cat("   🇧🇷 Portuguese/English: SUPPORTED\n")
cat("   🏛️ Government authorities: SPECIALIZED\n")

# Export main functions
CITATION_TEMPLATE_FUNCTIONS <- list(
  format_abnt_citation = format_abnt_citation,
  format_abnt_bibliography = format_abnt_bibliography,
  format_apa_citation = format_apa_citation,
  format_vancouver_citation = format_vancouver_citation,
  format_bluebook_citation = format_bluebook_citation,
  format_constitutional_citation = format_constitutional_citation,
  format_state_law_citation = format_state_law_citation,
  format_municipal_law_citation = format_municipal_law_citation,
  generate_multiple_citations = generate_multiple_citations,
  preview_citation_formats = preview_citation_formats,
  test_citation_templates = test_citation_templates
)