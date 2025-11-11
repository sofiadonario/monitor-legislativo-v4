# Text Normalization Utilities
# Monitor Legislativo v4 - Portuguese Text Readability Fixes
# ===========================================================

#' Fix Portuguese Text Spacing Issues
#'
#' Repairs common text issues in Portuguese legislative documents including:
#' - Words glued together (e.g., "TransportePúblico" -> "Transporte Público")
#' - Missing spaces after punctuation
#' - Excessive whitespace
#' - Proper handling of Portuguese legal terminology
#'
#' @param text Character vector of text to normalize
#' @param fix_camel_case Logical, whether to fix camelCase words (default TRUE)
#' @param preserve_acronyms Logical, whether to preserve uppercase acronyms (default TRUE)
#' @return Character vector with normalized spacing
#' @export
fix_portuguese_spacing <- function(text, fix_camel_case = TRUE, preserve_acronyms = TRUE) {

  if (is.null(text) || length(text) == 0) {
    return(character(0))
  }

  # Handle NA values
  text[is.na(text)] <- ""

  processed <- text

  # 1. Fix words glued together by detecting camelCase patterns
  # Pattern: lowercase letter followed by uppercase letter
  # Example: "TransportePúblico" -> "Transporte Público"
  if (fix_camel_case) {
    # Add space before uppercase letter that follows lowercase letter
    # But preserve acronyms (multiple consecutive uppercase letters)
    processed <- gsub("([a-zàáâãäåèéêëìíîïòóôõöùúûüýÿçñ])([A-ZÀÁÂÃÄÅÈÉÊËÌÍÎÏÒÓÔÕÖÙÚÛÜÝŸÇÑ])",
                     "\\1 \\2",
                     processed,
                     perl = TRUE)
  }

  # 2. Fix missing spaces after punctuation
  # Add space after period, comma, semicolon, colon (if not already there)
  processed <- gsub("([.,;:])([^ \\d])", "\\1 \\2", processed, perl = TRUE)

  # 3. Fix missing spaces before opening parentheses/brackets
  processed <- gsub("([^ ])([\\(\\[])", "\\1 \\2", processed, perl = TRUE)

  # 4. Fix missing spaces after closing parentheses/brackets
  processed <- gsub("([\\)\\]])([^ .,;:])", "\\1 \\2", processed, perl = TRUE)

  # 5. Normalize multiple spaces to single space
  processed <- gsub("\\s+", " ", processed, perl = TRUE)

  # 6. Trim leading/trailing whitespace
  processed <- trimws(processed)

  # 7. Preserve common Brazilian Portuguese legal acronyms (optional)
  if (preserve_acronyms) {
    # Keep acronyms together (e.g., "IBGE", "ANTT", "ANAC", "STF", "STJ")
    # This step is mostly handled by not splitting consecutive uppercase letters
  }

  return(processed)
}


#' Normalize Portuguese Legal Terminology
#'
#' Ensures consistent formatting of common legal terms and phrases
#'
#' @param text Character vector of text to normalize
#' @return Character vector with normalized terminology
#' @export
normalize_legal_terms <- function(text) {

  if (is.null(text) || length(text) == 0) {
    return(character(0))
  }

  text[is.na(text)] <- ""

  processed <- text

  # Common legal term corrections (case-insensitive replacement)
  legal_corrections <- list(
    # Transport terminology
    "transportepublico" = "transporte público",
    "transportepúblico" = "transporte público",
    "mobilidadeurbana" = "mobilidade urbana",
    "codigodetrânsito" = "código de trânsito",
    "codigodetrãnsito" = "código de trânsito",

    # Common legal phrases
    "direitoshumanos" = "direitos humanos",
    "saúdepública" = "saúde pública",
    "saudepublica" = "saúde pública",
    "educaçãobásica" = "educação básica",
    "educacaobasica" = "educação básica",
    "meioambiente" = "meio ambiente",
    "desenvolvimentosustentável" = "desenvolvimento sustentável",
    "desenvolvimentosustentavel" = "desenvolvimento sustentável",
    "segurançapública" = "segurança pública",
    "segurancapublica" = "segurança pública",
    "interessepúblico" = "interesse público",
    "interessepublico" = "interesse público",
    "poderpúblico" = "poder público",
    "poderpublico" = "poder público",
    "serviçopúblico" = "serviço público",
    "servicopublico" = "serviço público",
    "políticapública" = "política pública",
    "politicapublica" = "política pública",
    "ordempública" = "ordem pública",
    "ordempublica" = "ordem pública"
  )

  # Apply corrections
  for (wrong in names(legal_corrections)) {
    correct <- legal_corrections[[wrong]]
    # Case-insensitive replacement
    processed <- gsub(wrong, correct, processed, ignore.case = TRUE, perl = TRUE)
  }

  return(processed)
}


#' Comprehensive Text Cleanup for Display
#'
#' Applies all text normalization steps for optimal readability
#' in the user interface. Combines spacing fixes, terminology normalization,
#' and character encoding handling.
#'
#' @param text Character vector of text to clean
#' @param aggressive Logical, whether to apply aggressive corrections (default FALSE)
#' @return Character vector with cleaned text
#' @export
clean_text_for_display <- function(text, aggressive = FALSE) {

  if (is.null(text) || length(text) == 0) {
    return(character(0))
  }

  # Handle NA values
  text[is.na(text)] <- ""

  # Step 1: Fix spacing issues
  processed <- fix_portuguese_spacing(text,
                                      fix_camel_case = TRUE,
                                      preserve_acronyms = TRUE)

  # Step 2: Normalize legal terminology
  processed <- normalize_legal_terms(processed)

  # Step 3: Additional aggressive cleanup (if requested)
  if (aggressive) {
    # Remove excessive punctuation
    processed <- gsub("[.]{3,}", "...", processed)

    # Normalize quotes
    processed <- gsub("[\u201C\u201D\u201E\u201F\u2033\u2036]", '"', processed, perl = TRUE)
    processed <- gsub("[\u2018\u2019\u201A\u201B\u2032\u2035]", "'", processed, perl = TRUE)

    # Normalize dashes
    processed <- gsub("[\u2013\u2014\u2015]", "-", processed, perl = TRUE)
  }

  # Step 4: Final whitespace normalization
  processed <- gsub("\\s+", " ", processed)
  processed <- trimws(processed)

  # Ensure UTF-8 encoding
  Encoding(processed) <- "UTF-8"

  return(processed)
}


#' Validate Portuguese Text Quality
#'
#' Checks for common text quality issues in Portuguese legal documents
#'
#' @param text Character vector to validate
#' @return Data frame with quality metrics
#' @export
validate_text_quality <- function(text) {

  if (is.null(text) || length(text) == 0) {
    return(data.frame(
      has_glued_words = logical(0),
      has_encoding_issues = logical(0),
      has_excess_whitespace = logical(0),
      quality_score = numeric(0)
    ))
  }

  text[is.na(text)] <- ""

  results <- data.frame(
    text_length = nchar(text),
    has_glued_words = grepl("([a-zàáâãäåèéêëìíîïòóôõöùúûüýÿçñ])([A-ZÀÁÂÃÄÅÈÉÊËÌÍÎÏÒÓÔÕÖÙÚÛÜÝŸÇÑ])",
                           text, perl = TRUE),
    has_encoding_issues = grepl("[\uFFFD\u00BF\u00A1]", text, perl = TRUE),
    has_excess_whitespace = grepl("\\s{2,}", text, perl = TRUE),
    missing_punctuation_spaces = grepl("[.,;:]([^ \\d])", text, perl = TRUE)
  )

  # Calculate quality score (0-100)
  results$quality_score <- 100 - (
    (results$has_glued_words * 25) +
    (results$has_encoding_issues * 40) +
    (results$has_excess_whitespace * 15) +
    (results$missing_punctuation_spaces * 20)
  )

  return(results)
}


#' Apply Text Normalization to Data Frame Columns
#'
#' Applies text cleaning to specified columns in a data frame
#'
#' @param df Data frame containing text columns
#' @param columns Character vector of column names to clean
#' @param aggressive Logical, whether to apply aggressive corrections
#' @return Data frame with cleaned text columns
#' @export
clean_dataframe_text <- function(df, columns = c("titulo", "ementa", "assuntos"), aggressive = FALSE) {

  if (is.null(df) || nrow(df) == 0) {
    return(df)
  }

  # Check which columns exist
  columns_to_clean <- intersect(columns, names(df))

  if (length(columns_to_clean) == 0) {
    warning("No specified columns found in data frame")
    return(df)
  }

  # Apply cleaning to each column
  for (col in columns_to_clean) {
    if (is.character(df[[col]]) || is.factor(df[[col]])) {
      message(sprintf("Cleaning column: %s", col))
      df[[col]] <- clean_text_for_display(as.character(df[[col]]), aggressive = aggressive)
    }
  }

  return(df)
}


# Export all functions
.export_text_normalization <- function() {
  list(
    fix_portuguese_spacing = fix_portuguese_spacing,
    normalize_legal_terms = normalize_legal_terms,
    clean_text_for_display = clean_text_for_display,
    validate_text_quality = validate_text_quality,
    clean_dataframe_text = clean_dataframe_text
  )
}
