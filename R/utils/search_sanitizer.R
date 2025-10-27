# search_sanitizer.R - Search Input Sanitization and Normalization
# ============================================================================
# Purpose: Safely handle search inputs with accent normalization and escaping
# Created: 2025
# ============================================================================

library(stringi)

#' Sanitize and normalize search input
#'
#' @param query Search query string
#' @param preserve_accents Whether to preserve accented characters
#' @param escape_regex Whether to escape regex metacharacters
#' @return Sanitized query string
sanitize_search_query <- function(query, preserve_accents = TRUE, escape_regex = TRUE) {
  if (isTRUE(is.null(query)) || query == "") {
    return("")
  }

  # Remove potentially dangerous characters (SQL/XSS prevention)
  query <- gsub("[<>\"';]", "", query)

  # Trim whitespace
  query <- trimws(query)

  # Handle accent normalization
  if (!preserve_accents) {
    # Convert to ASCII transliteration
    query <- stri_trans_general(query, "Latin-ASCII")
  } else {
    # Normalize Unicode (NFC normalization)
    query <- stri_trans_nfc(query)
  }

  # Escape regex metacharacters if needed
  if (escape_regex) {
    query <- escape_regex_chars(query)
  }

  # Collapse multiple spaces
  query <- gsub("\\s+", " ", query)

  return(query)
}

#' Escape regex metacharacters
#'
#' @param text Text to escape
#' @return Text with escaped metacharacters
escape_regex_chars <- function(text) {
  if (isTRUE(is.null(text)) || length(text) == 0) {
    return(text)
  }

  specials <- c("\\", ".", "|", "(", ")", "[", "]", "{", "}", "^", "$", "*", "+", "?")

  for (char in specials) {
    pattern <- char
    replacement <- paste0("\\\\", char)

    if (char == "\\") {
      pattern <- "\\\\"
      replacement <- "\\\\\\\\"
    }

    text <- gsub(pattern, replacement, text, fixed = TRUE)
  }

  text
}

#' Create accent-insensitive regex pattern
#'
#' @param query Search query
#' @return Regex pattern that matches accented variations
create_accent_insensitive_pattern <- function(query) {
  if (isTRUE(is.null(query)) || query == "") {
    return("")
  }

  accent_map <- list(
    a = c("a", "á", "à", "â", "ã", "ä", "å"),
    e = c("e", "é", "è", "ê", "ë"),
    i = c("i", "í", "ì", "î", "ï"),
    o = c("o", "ó", "ò", "ô", "õ", "ö"),
    u = c("u", "ú", "ù", "û", "ü"),
    c = c("c", "ç"),
    n = c("n", "ñ")
  )

  chars <- strsplit(query, "", perl = TRUE)[[1]]

  parts <- vapply(chars, function(ch) {
    base <- stringi::stri_trans_general(ch, "Latin-ASCII")
    base_lower <- tolower(base)

    if (!isTRUE(is.na(base_lower)) && nzchar(base_lower) && base_lower %in% names(accent_map)) {
      variants <- accent_map[[base_lower]]
      variants <- unique(c(variants, toupper(variants)))
      escaped_variants <- vapply(variants, escape_regex_chars, character(1), USE.NAMES = FALSE)
      paste0("[", paste(escaped_variants, collapse = ""), "]")
    } else {
      escape_regex_chars(ch)
    }
  }, character(1), USE.NAMES = FALSE)

  paste(parts, collapse = "")
}

#' Validate and clean search suggestions
#'
#' @param suggestions Vector of suggestion strings
#' @param max_length Maximum length for each suggestion
#' @return Cleaned suggestions
clean_suggestions <- function(suggestions, max_length = 100) {
  if (isTRUE(is.null(suggestions)) || length(suggestions) == 0) {
    return(character(0))
  }

  # Remove duplicates
  suggestions <- unique(suggestions)

  # Clean each suggestion
  suggestions <- sapply(suggestions, function(s) {
    s <- trimws(s)
    # Remove script tags entirely
    s <- gsub("(?i)<script[^>]*?>.*?</script>", "", s, perl = TRUE)
    # Remove any HTML/script tags
    s <- gsub("<[^>]*>", "", s)
    # Limit length
    if (nchar(s) > max_length) {
      s <- substr(s, 1, max_length)
    }
    return(s)
  }, USE.NAMES = FALSE)

  # Remove empty strings
  suggestions <- suggestions[nchar(suggestions) > 0]

  return(suggestions)
}

#' Build safe SQL LIKE pattern
#'
#' @param query Search query
#' @param wildcard_position Where to place wildcards: "both", "start", "end", "none"
#' @return SQL LIKE pattern
build_sql_like_pattern <- function(query, wildcard_position = "both") {
  # Escape SQL wildcard characters
  query <- gsub("%", "\\%", query, fixed = TRUE)
  query <- gsub("_", "\\_", query, fixed = TRUE)

  # Add wildcards based on position
  pattern <- switch(wildcard_position,
    "both" = paste0("%", query, "%"),
    "start" = paste0("%", query),
    "end" = paste0(query, "%"),
    "none" = query,
    paste0("%", query, "%")  # Default to both
  )

  return(pattern)
}

#' Portuguese text normalization for search
#'
#' @param text Text to normalize
#' @param remove_stopwords Whether to remove Portuguese stopwords
#' @return Normalized text
normalize_portuguese_text <- function(text, remove_stopwords = TRUE) {
  # Portuguese stopwords
  portuguese_stopwords <- c(
    "a", "ao", "aos", "aquela", "aquelas", "aquele", "aqueles", "aquilo",
    "as", "até", "com", "como", "da", "das", "de", "dela", "delas", "dele",
    "deles", "depois", "do", "dos", "e", "ela", "elas", "ele", "eles", "em",
    "entre", "era", "essa", "essas", "esse", "esses", "esta", "estas", "este",
    "estes", "eu", "foi", "fomos", "foram", "há", "isso", "isto", "já", "lhe",
    "lhes", "mais", "mas", "me", "mesmo", "meu", "meus", "minha", "minhas",
    "muito", "na", "não", "nas", "nem", "no", "nos", "nós", "nossa", "nossas",
    "nosso", "nossos", "num", "numa", "o", "os", "ou", "para", "pela", "pelas",
    "pelo", "pelos", "por", "qual", "quando", "que", "quem", "são", "se", "sem",
    "seu", "seus", "só", "sua", "suas", "também", "te", "tem", "teu", "teus",
    "tu", "tua", "tuas", "um", "uma", "você", "vocês", "vos"
  )

  # Convert to lowercase
  text <- tolower(text)

  # Remove punctuation but keep spaces
  text <- gsub("[[:punct:]]", " ", text)

  # Split into words
  words <- unlist(strsplit(text, "\\s+"))

  # Remove empty strings
  words <- words[nchar(words) > 0]

  # Remove stopwords if requested
  if (remove_stopwords) {
    words <- words[!words %in% portuguese_stopwords]
  }

  # Rejoin words
  return(paste(words, collapse = " "))
}

#' Highlight search terms in text
#'
#' @param text Text to highlight in
#' @param search_terms Terms to highlight
#' @param before HTML/tag to insert before match
#' @param after HTML/tag to insert after match
#' @return Text with highlighted terms
highlight_search_terms <- function(text, search_terms,
                                 before = "<mark>", after = "</mark>") {
  if (isTRUE(is.null(text)) || isTRUE(is.null(search_terms)) || length(search_terms) == 0) {
    return(text)
  }

  # Sort terms by length (longest first) to avoid partial replacements
  search_terms <- search_terms[order(nchar(search_terms), decreasing = TRUE)]

  for (term in search_terms) {
    if (nchar(term) > 0) {
      # Create accent-insensitive pattern
      pattern <- create_accent_insensitive_pattern(term)
      pattern <- paste0(pattern, "(?:es|s)?")

      # Use backreference to preserve original case
      text <- gsub(paste0("(", pattern, ")"),
                  paste0(before, "\\1", after),
                  text,
                  ignore.case = TRUE)
    }
  }

  return(text)
}
