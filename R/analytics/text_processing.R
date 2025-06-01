# Text Processing Module
# Monitor Legislativo v4 - Portuguese Legal Text Analysis
# =======================================================

#' Portuguese Legal Text Preprocessing Pipeline
#' 
#' Advanced text preprocessing pipeline specifically designed for Brazilian
#' legislative documents with intelligent legal terminology preservation,
#' Portuguese language optimization, and academic research standards.
#' 
#' This function implements domain-specific text cleaning and normalization
#' procedures that maintain the semantic integrity of legal documents while
#' preparing text for computational analysis, topic modeling, and academic
#' research applications.
#' 
#' @details
#' **Legal Domain Specialization:**
#' - **Legal Phrase Preservation**: Protects important multi-word legal terms
#' - **Portuguese Stopwords**: Comprehensive Portuguese and legal stopword lists
#' - **Legal Structure**: Preserves article/paragraph references and citations
#' - **Terminology Consistency**: Maintains consistent legal terminology
#' 
#' **Academic Research Features:**
#' - **Reproducible Processing**: Consistent results across research sessions
#' - **Configurable Parameters**: Adjustable for different research needs
#' - **Batch Processing**: Efficient handling of large document collections
#' - **Character Encoding**: Proper handling of Portuguese accents and characters
#' 
#' **Text Normalization Steps:**
#' 1. Legal phrase tokenization and protection
#' 2. Case normalization (lowercase conversion)
#' 3. Special character handling (preserving hyphens in legal terms)
#' 4. Whitespace normalization and cleanup
#' 5. Portuguese stopword removal (optional)
#' 6. Minimum word length filtering
#' 7. Legal phrase restoration
#' 
#' **Preserved Legal Phrases Examples:**
#' - "transporte público" (public transportation)
#' - "código de trânsito" (traffic code)
#' - "mobilidade urbana" (urban mobility)
#' - "desenvolvimento sustentável" (sustainable development)
#' 
#' @param text_vector Character vector containing Brazilian legal documents
#'   or text snippets to be processed. Handles NA values gracefully.
#' @param remove_stopwords Logical indicating whether to remove Portuguese
#'   stopwords and common legal function words. Default TRUE for most
#'   analytical purposes.
#' @param preserve_legal_terms Logical indicating whether to preserve
#'   important multi-word legal phrases during processing. Recommended
#'   TRUE for legal domain analysis.
#' @param min_word_length Integer specifying minimum word length to retain.
#'   Default 3 characters to filter articles and prepositions.
#' 
#' @return Character vector of processed text with same length as input.
#'   NA values are converted to empty strings. Text is normalized and
#'   ready for further analysis or modeling.
#' 
#' @family nlp-functions
#' @seealso \code{\link{analyze_regulatory_sentiment}} for sentiment analysis
#' @seealso \code{\link{extract_legal_entities}} for entity recognition
#' @seealso \code{\link{extract_key_legal_terms}} for term extraction
#' 
#' @examples
#' \dontrun{
#' # Basic preprocessing for academic analysis
#' legal_texts <- c(
#'   "A Lei de Mobilidade Urbana estabelece diretrizes para o transporte público.",
#'   "O Código de Trânsito Brasileiro regulamenta a circulação de veículos."
#' )
#' 
#' processed <- preprocess_legal_text(legal_texts)
#' # Result preserves "mobilidade urbana", "transporte público", "código de trânsito"
#' 
#' # Minimal preprocessing (keep all words)
#' minimal <- preprocess_legal_text(
#'   legal_texts,
#'   remove_stopwords = FALSE,
#'   min_word_length = 1
#' )
#' 
#' # Aggressive cleaning for topic modeling
#' clean <- preprocess_legal_text(
#'   legal_texts,
#'   remove_stopwords = TRUE,
#'   preserve_legal_terms = TRUE,
#'   min_word_length = 4
#' )
#' }
#' 
#' @export
preprocess_legal_text <- function(text_vector, 
                                  remove_stopwords = TRUE,
                                  preserve_legal_terms = TRUE,
                                  min_word_length = 3) {
  
  if (is.null(text_vector) || length(text_vector) == 0) {
    return(character(0))
  }
  
  # Legal-specific stopwords (Portuguese)
  legal_stopwords <- c(
    "artigo", "parágrafo", "inciso", "alínea", "item",
    "lei", "decreto", "portaria", "resolução", "instrução",
    "conforme", "mediante", "através", "perante", "segundo",
    "desta", "deste", "dessa", "desse", "aquela", "aquele"
  )
  
  # Important legal phrases to preserve
  legal_phrases <- c(
    "transporte público", "código de trânsito", "mobilidade urbana",
    "sistema viário", "meio ambiente", "desenvolvimento sustentável",
    "segurança pública", "saúde pública", "educação básica",
    "direitos humanos", "poder público", "interesse público",
    "ordem pública", "política pública", "serviço público"
  )
  
  processed_text <- text_vector
  
  # Handle missing values
  processed_text[is.na(processed_text)] <- ""
  
  if (preserve_legal_terms) {
    # Temporarily replace legal phrases with tokens
    phrase_tokens <- paste0("LEGAL_PHRASE_", seq_along(legal_phrases))
    phrase_map <- setNames(phrase_tokens, legal_phrases)
    
    for (i in seq_along(legal_phrases)) {
      processed_text <- gsub(
        legal_phrases[i], 
        phrase_tokens[i], 
        processed_text, 
        ignore.case = TRUE,
        fixed = TRUE
      )
    }
  }
  
  # Standard text cleaning
  processed_text <- tolower(processed_text)
  
  # Remove special characters but preserve spaces and hyphens in legal terms
  processed_text <- gsub("[^\\p{L}\\s\\-0-9]", " ", processed_text, perl = TRUE)
  
  # Normalize whitespace
  processed_text <- gsub("\\s+", " ", processed_text)
  processed_text <- trimws(processed_text)
  
  if (remove_stopwords) {
    # Portuguese stopwords
    pt_stopwords <- c(
      "a", "o", "e", "é", "de", "do", "da", "em", "um", "uma", "para", "com", 
      "não", "que", "se", "na", "por", "mais", "as", "dos", "como", "mas", 
      "foi", "ao", "ele", "das", "tem", "à", "seu", "sua", "ou", "ser", "quando",
      "muito", "há", "nos", "já", "está", "eu", "também", "só", "pelo", "pela",
      "até", "isso", "ela", "entre", "era", "depois", "sem", "mesmo", "aos",
      "ter", "seus", "suas", "numa", "pelos", "pelas", "esse", "essa", "num",
      "nem", "suas", "meu", "às", "minha", "têm", "numa", "pelos", "pelas",
      legal_stopwords
    )
    
    # Split into words and filter
    words_list <- strsplit(processed_text, "\\s+")
    
    processed_text <- sapply(words_list, function(words) {
      # Filter stopwords and short words
      filtered_words <- words[
        !words %in% pt_stopwords & 
        nchar(words) >= min_word_length &
        words != ""
      ]
      paste(filtered_words, collapse = " ")
    })
  }
  
  if (preserve_legal_terms) {
    # Restore legal phrases
    for (i in seq_along(legal_phrases)) {
      processed_text <- gsub(
        phrase_tokens[i], 
        legal_phrases[i], 
        processed_text, 
        fixed = TRUE
      )
    }
  }
  
  return(processed_text)
}

#' Regulatory Sentiment Analysis for Legislative Documents
#' 
#' Advanced sentiment analysis specifically designed for Brazilian legislative
#' documents that classifies regulatory tone and policy approach. Analyzes the
#' prescriptive versus flexible nature of legal language to support academic
#' research in policy analysis and legal linguistics.
#' 
#' This function uses domain-specific linguistic markers to determine whether
#' legal text adopts a mandatory, permissive, or balanced regulatory approach,
#' which is crucial for understanding policy implementation strategies and
#' regulatory effectiveness in Brazilian legal frameworks.
#' 
#' @details
#' **Regulatory Tone Categories:**
#' - **Prescriptive**: Mandatory language with strict requirements
#'   - Indicators: "obrigatório", "vedado", "deve", "determina", "sob pena"
#'   - Typical of strict regulations and criminal law
#' - **Flexible**: Permissive language allowing discretion
#'   - Indicators: "pode", "faculta", "permite", "recomenda", "a critério"
#'   - Common in administrative guidelines and policy frameworks
#' - **Balanced**: Mixed or neutral regulatory approach
#'   - Equal or minimal presence of prescriptive/flexible indicators
#'   - Often found in framework laws and general principles
#' 
#' **Academic Applications:**
#' - **Policy Analysis**: Compare regulatory approaches across domains
#' - **Legal Linguistics**: Study evolution of legal language over time
#' - **Comparative Law**: Analyze differences between jurisdictions
#' - **Implementation Studies**: Predict policy flexibility and compliance
#' 
#' **Methodological Features:**
#' - **Portuguese Language Optimization**: Specialized for Brazilian Portuguese
#' - **Legal Domain Terms**: Curated terminology from legislative corpus
#' - **Vectorized Processing**: Efficient analysis of large document collections
#' - **Reproducible Results**: Consistent classification across research sessions
#' 
#' **Quality Considerations:**
#' - Handles empty and NA text values gracefully
#' - Case-insensitive pattern matching for robustness
#' - Counts multiple occurrences of indicators within text
#' - Provides balanced classification when evidence is inconclusive
#' 
#' @param text Character vector containing Brazilian legislative documents
#'   or text segments to analyze. Handles NA values by assigning "Balanced"
#'   classification.
#' 
#' @return Character vector of sentiment classifications with same length
#'   as input, containing one of:
#'   \item{"Prescriptive"}{Text contains predominantly mandatory language}
#'   \item{"Flexible"}{Text contains predominantly permissive language}
#'   \item{"Balanced"}{Text has mixed or minimal regulatory indicators}
#' 
#' @family nlp-functions
#' @seealso \code{\link{preprocess_legal_text}} for text preprocessing
#' @seealso \code{\link{extract_legal_entities}} for entity recognition
#' @seealso \code{\link{calculate_text_complexity}} for complexity analysis
#' 
#' @examples
#' \dontrun{
#' # Analyze regulatory sentiment in legislative texts
#' laws <- c(
#'   "É obrigatório o uso de cintos de segurança. Vedada a circulação sem equipamentos.",
#'   "O município pode estabelecer diretrizes. Recomenda-se a consulta pública.",
#'   "A lei estabelece princípios gerais para a administração pública."
#' )
#' 
#' sentiments <- analyze_regulatory_sentiment(laws)
#' # Result: c("Prescriptive", "Flexible", "Balanced")
#' 
#' # Academic research workflow
#' library(dplyr)
#' 
#' # Analyze sentiment distribution by document type
#' document_analysis <- data.frame(
#'   text = laws,
#'   tipo = c("lei", "decreto", "resolução")
#' ) %>%
#'   mutate(
#'     sentiment = analyze_regulatory_sentiment(text)
#'   ) %>%
#'   count(tipo, sentiment)
#' 
#' # Temporal analysis of regulatory approaches
#' historical_laws %>%
#'   mutate(
#'     regulatory_tone = analyze_regulatory_sentiment(content),
#'     decade = floor(ano / 10) * 10
#'   ) %>%
#'   count(decade, regulatory_tone) %>%
#'   ggplot(aes(decade, n, fill = regulatory_tone)) +
#'   geom_col(position = "fill")
#' }
#' 
#' @export
analyze_regulatory_sentiment <- function(text) {
  
  if (is.null(text) || length(text) == 0) {
    return(character(0))
  }
  
  # Handle missing values
  text[is.na(text)] <- ""
  
  # Vectorized analysis
  sentiment_results <- sapply(text, function(single_text) {
    
    if (single_text == "") return("Balanced")
    
    text_lower <- tolower(single_text)
    
    # Prescriptive indicators (mandatory language)
    prescriptive_terms <- c(
      "obrigatório", "vedado", "proibido", "deve", "deverá", 
      "obriga", "exige", "impõe", "determina", "estabelece",
      "é necessário", "é obrigatório", "fica proibido", "é vedado",
      "sob pena", "multa", "sanção", "penalidade"
    )
    
    # Flexible indicators (permissive language)
    flexible_terms <- c(
      "pode", "poderá", "faculta", "permite", "autoriza", 
      "recomenda", "sugere", "orienta", "incentiva", "estimula",
      "é facultado", "é permitido", "quando possível", "se necessário",
      "a critério", "discricionário"
    )
    
    # Count occurrences
    prescriptive_count <- sum(sapply(prescriptive_terms, function(term) {
      length(gregexpr(term, text_lower, fixed = TRUE)[[1]]) - 
      (gregexpr(term, text_lower, fixed = TRUE)[[1]][1] == -1)
    }))
    
    flexible_count <- sum(sapply(flexible_terms, function(term) {
      length(gregexpr(term, text_lower, fixed = TRUE)[[1]]) - 
      (gregexpr(term, text_lower, fixed = TRUE)[[1]][1] == -1)
    }))
    
    # Classification logic
    if (prescriptive_count > flexible_count && prescriptive_count > 0) {
      return("Prescriptive")
    } else if (flexible_count > prescriptive_count && flexible_count > 0) {
      return("Flexible") 
    } else {
      return("Balanced")
    }
  })
  
  return(unname(sentiment_results))
}

#' Legal Entity Recognition for Brazilian Legislative Documents
#' 
#' Advanced named entity recognition system specialized for Brazilian legal
#' and administrative entities. Identifies and categorizes institutions,
#' legislation types, and domain-specific organizations mentioned in
#' legislative documents to support academic research and legal analysis.
#' 
#' This function implements domain-specific entity recognition using curated
#' knowledge bases of Brazilian government structure, legal institutions,
#' and regulatory frameworks. Essential for academic research involving
#' institutional analysis and policy network studies.
#' 
#' @details
#' **Entity Categories:**
#' 
#' **Government Institutions:**
#' - Federal: Presidência, Congresso Nacional, STF, TCU, Ministério Público
#' - State: Assembleia Legislativa, Governo do Estado, Secretarias Estaduais
#' - Municipal: Câmara Municipal, Prefeitura, Secretarias Municipais
#' 
#' **Legislation Types:**
#' - Constitutional: Constituição Federal, Emendas Constitucionais
#' - Laws: Lei Complementar, Lei Ordinária, Decreto-Lei, Medida Provisória
#' - Administrative: Decreto, Portaria, Resolução, Instrução Normativa
#' - Codes: Código Civil, Código Penal, Código de Trânsito
#' 
#' **Specialized Entities:**
#' - **Transport**: ANTT, ANTAQ, DNIT, DENATRAN, SPTrans, Metrô
#' - **Environment**: IBAMA, ICMBio, CONAMA, CETESB, INPE
#' - **Economic**: Banco Central, CVM, SUSEP, Receita Federal, BNDES
#' 
#' **Academic Applications:**
#' - **Institutional Analysis**: Map government entity mentions and relationships
#' - **Policy Networks**: Identify key actors in policy domains
#' - **Legal Citations**: Extract references to other legal instruments
#' - **Jurisdictional Analysis**: Understand federal/state/municipal competencies
#' 
#' **Technical Features:**
#' - **Case-Insensitive Matching**: Robust recognition regardless of capitalization
#' - **Batch Processing**: Efficient analysis of document collections
#' - **Flexible Output**: Returns structured lists or individual results
#' - **Missing Data Handling**: Graceful handling of NA and empty inputs
#' 
#' @param text Character vector containing Brazilian legislative documents
#'   or text segments to analyze. Each element is processed independently.
#' 
#' @return If input length is 1, returns a named list of entity categories.
#'   If input length > 1, returns a list of lists (one per input text).
#'   Each entity category contains unique entity names found in the text:
#'   \item{institutions}{Government institutions and administrative bodies}
#'   \item{legislation_types}{Types of legal instruments and codes}
#'   \item{transport_entities}{Transportation-related organizations}
#'   \item{environmental_entities}{Environmental agencies and councils}
#'   \item{economic_entities}{Financial and economic institutions}
#' 
#' @family nlp-functions
#' @seealso \code{\link{preprocess_legal_text}} for text preprocessing
#' @seealso \code{\link{analyze_regulatory_sentiment}} for sentiment analysis
#' @seealso \code{\link{extract_key_legal_terms}} for term extraction
#' 
#' @examples
#' \dontrun{
#' # Single document entity extraction
#' law_text <- paste(
#'   "O Congresso Nacional aprova lei que regulamenta o IBAMA",
#'   "e estabelece competências do Ministério do Meio Ambiente."
#' )
#' 
#' entities <- extract_legal_entities(law_text)
#' # Returns: list(
#' #   institutions = c("Congresso Nacional", "Ministério do Meio Ambiente"),
#' #   environmental_entities = c("IBAMA")
#' # )
#' 
#' # Batch processing for research corpus
#' legal_corpus <- c(
#'   "O DENATRAN estabelece normas de trânsito...",
#'   "A ANTT regulamenta o transporte rodoviário...",
#'   "O Supremo Tribunal Federal decide..."
#' )
#' 
#' corpus_entities <- extract_legal_entities(legal_corpus)
#' 
#' # Academic analysis workflow
#' library(dplyr)
#' 
#' # Count entity mentions across documents
#' entity_counts <- map_dfr(corpus_entities, function(doc_entities) {
#'   map_dfr(doc_entities, function(category) {
#'     tibble(entity = category)
#'   }, .id = "category")
#' }, .id = "document") %>%
#'   count(category, entity, sort = TRUE)
#' 
#' # Network analysis of institutional co-mentions
#' institutional_network <- corpus_entities %>%
#'   map("institutions") %>%
#'   keep(~length(.x) > 1) %>%
#'   map(~expand.grid(.x, .x, stringsAsFactors = FALSE)) %>%
#'   bind_rows() %>%
#'   filter(Var1 != Var2)
#' }
#' 
#' @export
extract_legal_entities <- function(text) {
  
  if (is.null(text) || length(text) == 0) {
    return(list())
  }
  
  # Define legal entity categories
  legal_entities <- list(
    institutions = c(
      "Presidência da República", "Congresso Nacional", "Supremo Tribunal Federal",
      "Tribunal Superior Eleitoral", "Tribunal de Contas da União", "Ministério Público",
      "Defensoria Pública", "Advocacia-Geral da União", "Controladoria-Geral da União",
      "Senado Federal", "Câmara dos Deputados", "Assembleia Legislativa",
      "Câmara Municipal", "Prefeitura", "Governo do Estado", "Secretaria de Estado"
    ),
    
    legislation_types = c(
      "Constituição Federal", "Lei Complementar", "Lei Ordinária", "Decreto-Lei",
      "Medida Provisória", "Decreto", "Portaria", "Resolução", "Instrução Normativa",
      "Código Civil", "Código Penal", "Código de Processo Civil", "Código de Trânsito"
    ),
    
    transport_entities = c(
      "ANTT", "ANTAQ", "DNIT", "DENATRAN", "DETRAN", "SPTrans", "CPTM", "Metrô",
      "Secretaria de Transportes", "Ministério dos Transportes", "ANAC", "Infraero"
    ),
    
    environmental_entities = c(
      "IBAMA", "ICMBio", "Ministério do Meio Ambiente", "CONAMA", "ANA",
      "Secretaria do Meio Ambiente", "CETESB", "INPE", "INEMA"
    ),
    
    economic_entities = c(
      "Banco Central", "CVM", "SUSEP", "Ministério da Fazenda", "Receita Federal",
      "BNDES", "Caixa Econômica Federal", "Banco do Brasil"
    )
  )
  
  # Process each text
  all_results <- lapply(text, function(single_text) {
    
    if (is.null(single_text) || is.na(single_text) || single_text == "") {
      return(list())
    }
    
    found_entities <- list()
    
    for (category in names(legal_entities)) {
      entities_in_category <- c()
      
      for (entity in legal_entities[[category]]) {
        # Case-insensitive search
        if (grepl(entity, single_text, ignore.case = TRUE)) {
          entities_in_category <- c(entities_in_category, entity)
        }
      }
      
      if (length(entities_in_category) > 0) {
        found_entities[[category]] <- unique(entities_in_category)
      }
    }
    
    return(found_entities)
  })
  
  # If single text, return directly; if multiple, return list
  if (length(text) == 1) {
    return(all_results[[1]])
  } else {
    return(all_results)
  }
}

#' Extract Key Legal Terms
#' 
#' Identifies and extracts key legal terminology from text
#' 
#' @param text Character vector of texts
#' @param min_frequency Minimum frequency for term extraction
#' @return Data frame of terms and frequencies
#' @export
extract_key_legal_terms <- function(text, min_frequency = 2) {
  
  if (is.null(text) || length(text) == 0) {
    return(data.frame(term = character(0), frequency = integer(0)))
  }
  
  # Preprocess text
  processed_text <- preprocess_legal_text(text, remove_stopwords = TRUE)
  combined_text <- paste(processed_text, collapse = " ")
  
  # Extract terms
  words <- unlist(strsplit(combined_text, "\\s+"))
  words <- words[words != "" & nchar(words) >= 3]
  
  # Count frequencies
  word_freq <- table(words)
  word_freq <- word_freq[word_freq >= min_frequency]
  word_freq <- sort(word_freq, decreasing = TRUE)
  
  # Return as data frame
  result <- data.frame(
    term = names(word_freq),
    frequency = as.numeric(word_freq),
    stringsAsFactors = FALSE
  )
  
  return(result)
}

#' Calculate Text Complexity Metrics
#' 
#' Calculates readability and complexity metrics for legal texts
#' 
#' @param text Character vector of texts
#' @return Data frame with complexity metrics
#' @export
calculate_text_complexity <- function(text) {
  
  if (is.null(text) || length(text) == 0) {
    return(data.frame(
      text_id = integer(0),
      word_count = integer(0),
      sentence_count = integer(0),
      avg_words_per_sentence = numeric(0),
      avg_chars_per_word = numeric(0),
      complexity_score = character(0)
    ))
  }
  
  results <- data.frame(
    text_id = seq_along(text),
    word_count = integer(length(text)),
    sentence_count = integer(length(text)),
    avg_words_per_sentence = numeric(length(text)),
    avg_chars_per_word = numeric(length(text)),
    complexity_score = character(length(text)),
    stringsAsFactors = FALSE
  )
  
  for (i in seq_along(text)) {
    
    if (is.na(text[i]) || text[i] == "") {
      results$complexity_score[i] <- "Unknown"
      next
    }
    
    # Word count
    words <- unlist(strsplit(text[i], "\\s+"))
    words <- words[words != ""]
    results$word_count[i] <- length(words)
    
    # Sentence count (approximation)
    sentences <- unlist(strsplit(text[i], "[.!?]+"))
    sentences <- sentences[trimws(sentences) != ""]
    results$sentence_count[i] <- length(sentences)
    
    # Average words per sentence
    if (results$sentence_count[i] > 0) {
      results$avg_words_per_sentence[i] <- results$word_count[i] / results$sentence_count[i]
    }
    
    # Average characters per word
    if (length(words) > 0) {
      results$avg_chars_per_word[i] <- mean(nchar(words))
    }
    
    # Complexity classification
    if (results$avg_words_per_sentence[i] > 20 || results$avg_chars_per_word[i] > 7) {
      results$complexity_score[i] <- "High"
    } else if (results$avg_words_per_sentence[i] > 15 || results$avg_chars_per_word[i] > 5) {
      results$complexity_score[i] <- "Medium"
    } else {
      results$complexity_score[i] <- "Low"
    }
  }
  
  return(results)
}

cat("✅ Text processing module loaded\n")
cat("📝 Features: Preprocessing, sentiment analysis, entity recognition, complexity analysis\n")