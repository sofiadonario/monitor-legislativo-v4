# Document Processing Pipeline for Monitor Legislativo v4
# Advanced document processing, classification, and batch operations

library(dplyr)
library(stringr)
library(lubridate)
library(textcat)
library(future)
library(promises)

# Document processing configuration
PIPELINE_CONFIG <- list(
  max_batch_size = 100,
  processing_timeout = 300,  # 5 minutes
  enable_text_analysis = TRUE,
  enable_classification = TRUE,
  enable_quality_scoring = TRUE,
  enable_metadata_extraction = TRUE,
  min_document_quality = 60  # Minimum quality score (0-100)
)

#' Main document processing pipeline
#' @param documents Data frame with documents to process
#' @param options Processing options
#' @return Processed documents with enhanced metadata
process_document_pipeline <- function(documents, options = list()) {
  
  if (is.null(documents) || nrow(documents) == 0) {
    log_event("No documents to process", "WARN")
    return(create_empty_search_result())
  }
  
  log_event(paste("Starting document pipeline for", nrow(documents), "documents"))
  
  # Merge options with defaults
  pipeline_options <- modifyList(PIPELINE_CONFIG, options)
  
  # Process in batches for performance
  batch_size <- min(pipeline_options$max_batch_size, nrow(documents))
  batches <- split(documents, ceiling(seq_nrow(documents) / batch_size))
  
  processed_batches <- list()
  
  for (i in seq_along(batches)) {
    batch <- batches[[i]]
    log_event(paste("Processing batch", i, "of", length(batches), "- size:", nrow(batch)))
    
    tryCatch({
      processed_batch <- process_document_batch(batch, pipeline_options)
      processed_batches[[i]] <- processed_batch
    }, error = function(e) {
      log_event(paste("Error processing batch", i, ":", e$message), "ERROR")
      processed_batches[[i]] <- batch  # Return unprocessed batch
    })
  }
  
  # Combine all processed batches
  final_documents <- do.call(rbind, processed_batches)
  
  # Apply final quality filters
  quality_filtered <- apply_quality_filters(final_documents, pipeline_options)
  
  log_event(paste("Document pipeline completed:", nrow(quality_filtered), "documents processed"))
  
  return(quality_filtered)
}

#' Process a batch of documents
#' @param batch Documents batch
#' @param options Processing options
#' @return Processed batch
process_document_batch <- function(batch, options) {
  
  # Stage 1: Basic validation and cleaning
  cleaned_batch <- clean_document_data(batch)
  
  # Stage 2: Metadata extraction
  if (options$enable_metadata_extraction) {
    metadata_enhanced <- extract_document_metadata(cleaned_batch)
  } else {
    metadata_enhanced <- cleaned_batch
  }
  
  # Stage 3: Text analysis
  if (options$enable_text_analysis) {
    text_analyzed <- perform_text_analysis(metadata_enhanced)
  } else {
    text_analyzed <- metadata_enhanced
  }
  
  # Stage 4: Document classification
  if (options$enable_classification) {
    classified <- classify_documents(text_analyzed)
  } else {
    classified <- text_analyzed
  }
  
  # Stage 5: Quality scoring
  if (options$enable_quality_scoring) {
    quality_scored <- score_document_quality(classified)
  } else {
    quality_scored <- classified
  }
  
  # Stage 6: Additional processing
  final_processed <- enhance_document_metadata(quality_scored)
  
  return(final_processed)
}

#' Clean and standardize document data
#' @param documents Raw documents
#' @return Cleaned documents
clean_document_data <- function(documents) {
  
  log_event("Cleaning document data")
  
  cleaned <- documents %>%
    mutate(
      # Clean and normalize titles
      titulo = str_trim(str_squish(titulo)),
      titulo = str_to_title(titulo),
      titulo = ifelse(nchar(titulo) < 5, "Documento sem título adequado", titulo),
      
      # Clean document numbers
      numero = str_trim(str_replace_all(numero, "[^0-9A-Za-z/.-]", "")),
      numero = ifelse(nchar(numero) == 0, NA, numero),
      
      # Standardize document types
      tipo = standardize_document_types(tipo),
      
      # Clean and validate dates
      data = parse_and_validate_dates(data),
      
      # Clean ementas (summaries)
      ementa = str_trim(str_squish(ementa)),
      ementa = ifelse(nchar(ementa) < 10, NA, ementa),
      
      # Clean author fields
      autor = str_trim(str_squish(autor)),
      autor = str_to_title(autor),
      
      # Standardize state codes
      estado = standardize_state_codes_pipeline(estado),
      
      # Clean URLs
      url = clean_document_urls(url),
      
      # Add processing timestamp
      data_processamento = Sys.time()
    ) %>%
    # Remove obviously invalid documents
    filter(
      !is.na(titulo),
      nchar(titulo) >= 5,
      !is.na(data) | !is.na(numero)  # Must have either date or number
    )
  
  return(cleaned)
}

#' Standardize document types
#' @param types Vector of document types
#' @return Standardized types
standardize_document_types <- function(types) {
  
  sapply(types, function(type) {
    if (is.na(type) || nchar(str_trim(type)) == 0) {
      return("Tipo não especificado")
    }
    
    type_lower <- str_to_lower(str_trim(type))
    
    # Map variations to standard types
    if (str_detect(type_lower, "lei.*complementar")) return("Lei Complementar")
    if (str_detect(type_lower, "lei.*ordinaria|^lei$")) return("Lei Ordinária")
    if (str_detect(type_lower, "decreto.*lei")) return("Decreto-Lei")
    if (str_detect(type_lower, "decreto")) return("Decreto")
    if (str_detect(type_lower, "medida.*provisoria")) return("Medida Provisória")
    if (str_detect(type_lower, "portaria")) return("Portaria")
    if (str_detect(type_lower, "resolucao|resolução")) return("Resolução")
    if (str_detect(type_lower, "instrucao.*normativa|instrução.*normativa")) return("Instrução Normativa")
    if (str_detect(type_lower, "ordem.*servico|ordem.*serviço")) return("Ordem de Serviço")
    if (str_detect(type_lower, "circular")) return("Circular")
    if (str_detect(type_lower, "parecer")) return("Parecer")
    if (str_detect(type_lower, "emenda")) return("Emenda")
    if (str_detect(type_lower, "constituicao|constituição")) return("Constituição")
    
    # Return cleaned version if no match
    return(str_to_title(type))
  })
}

#' Parse and validate document dates
#' @param dates Vector of date strings
#' @return Vector of validated Date objects
parse_and_validate_dates <- function(dates) {
  
  parsed_dates <- sapply(dates, function(date_str) {
    
    if (is.na(date_str) || nchar(str_trim(date_str)) == 0) {
      return(NA)
    }
    
    # Try multiple date formats
    formats <- c(
      "%Y-%m-%d",
      "%d/%m/%Y", 
      "%Y/%m/%d",
      "%d-%m-%Y",
      "%Y-%m-%dT%H:%M:%S",
      "%Y-%m-%d %H:%M:%S"
    )
    
    for (fmt in formats) {
      tryCatch({
        parsed <- as.Date(date_str, format = fmt)
        if (!is.na(parsed)) {
          # Validate reasonable date range
          if (parsed >= as.Date("1500-01-01") && parsed <= Sys.Date() + 365) {
            return(parsed)
          }
        }
      }, error = function(e) {
        # Continue to next format
      })
    }
    
    # Last resort: try automatic parsing
    tryCatch({
      auto_parsed <- as.Date(date_str)
      if (!is.na(auto_parsed)) {
        if (auto_parsed >= as.Date("1500-01-01") && auto_parsed <= Sys.Date() + 365) {
          return(auto_parsed)
        }
      }
    }, error = function(e) {
      # Give up
    })
    
    return(NA)
  })
  
  return(as.Date(parsed_dates, origin = "1970-01-01"))
}

#' Standardize state codes for pipeline
#' @param states Vector of state strings
#' @return Standardized state codes
standardize_state_codes_pipeline <- function(states) {
  
  valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
                   "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
                   "RS", "RO", "RR", "SC", "SP", "SE", "TO", "BR")
  
  sapply(states, function(state) {
    if (is.na(state) || nchar(str_trim(state)) == 0) {
      return(NA)
    }
    
    # Extract state code from various formats
    state_clean <- str_to_upper(str_trim(state))
    
    # Direct match
    if (state_clean %in% valid_states) {
      return(state_clean)
    }
    
    # Try to extract from jurisdiction string (e.g., "br;sp")
    if (str_detect(state_clean, ";")) {
      parts <- str_split(state_clean, ";")[[1]]
      if (length(parts) >= 2) {
        state_part <- str_to_upper(parts[2])
        if (state_part %in% valid_states) {
          return(state_part)
        }
      }
    }
    
    # Try state name mapping
    state_lower <- str_to_lower(state)
    state_mapping <- list(
      "acre" = "AC", "alagoas" = "AL", "amapa" = "AP", "amazonas" = "AM",
      "bahia" = "BA", "ceara" = "CE", "distrito federal" = "DF", 
      "espirito santo" = "ES", "goias" = "GO", "maranhao" = "MA",
      "mato grosso" = "MT", "mato grosso do sul" = "MS", "minas gerais" = "MG",
      "para" = "PA", "paraiba" = "PB", "parana" = "PR", "pernambuco" = "PE",
      "piaui" = "PI", "rio de janeiro" = "RJ", "rio grande do norte" = "RN",
      "rio grande do sul" = "RS", "rondonia" = "RO", "roraima" = "RR",
      "santa catarina" = "SC", "sao paulo" = "SP", "sergipe" = "SE", "tocantins" = "TO"
    )
    
    for (name in names(state_mapping)) {
      if (str_detect(state_lower, name)) {
        return(state_mapping[[name]])
      }
    }
    
    return(NA)
  })
}

#' Clean document URLs
#' @param urls Vector of URLs
#' @return Cleaned URLs
clean_document_urls <- function(urls) {
  
  sapply(urls, function(url) {
    if (is.na(url) || nchar(str_trim(url)) == 0) {
      return(NA)
    }
    
    url_clean <- str_trim(url)
    
    # Add protocol if missing
    if (!str_detect(url_clean, "^https?://")) {
      url_clean <- paste0("https://", url_clean)
    }
    
    # Basic URL validation
    if (str_detect(url_clean, "^https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")) {
      return(url_clean)
    }
    
    return(NA)
  })
}

#' Extract document metadata
#' @param documents Cleaned documents
#' @return Documents with extracted metadata
extract_document_metadata <- function(documents) {
  
  log_event("Extracting document metadata")
  
  enhanced <- documents %>%
    mutate(
      # Document age metrics
      dias_desde_publicacao = as.numeric(Sys.Date() - data),
      ano_publicacao = year(data),
      mes_publicacao = month(data),
      
      # Text metrics
      titulo_palavras = str_count(titulo, "\\S+"),
      titulo_caracteres = nchar(titulo),
      ementa_palavras = ifelse(!is.na(ementa), str_count(ementa, "\\S+"), 0),
      ementa_caracteres = ifelse(!is.na(ementa), nchar(ementa), 0),
      
      # Authority level extraction
      nivel_autoridade = extract_authority_level_pipeline(autor, tipo),
      
      # Geographic region mapping
      regiao = map_state_to_region_pipeline(estado),
      
      # Document complexity estimation
      complexidade_estimada = estimate_document_complexity(titulo, ementa, tipo),
      
      # Legal hierarchy level
      hierarquia_legal = determine_legal_hierarchy(tipo),
      
      # Publication pattern
      padrao_publicacao = analyze_publication_pattern(data, tipo)
    )
  
  return(enhanced)
}

#' Extract authority level from document data
#' @param authors Vector of authors
#' @param types Vector of document types
#' @return Vector of authority levels
extract_authority_level_pipeline <- function(authors, types) {
  
  mapply(function(author, type) {
    
    # Start with type-based classification
    if (!is.na(type)) {
      type_lower <- str_to_lower(type)
      
      if (str_detect(type_lower, "constituicao|emenda.*constitucional")) {
        return("Constitucional")
      }
      if (str_detect(type_lower, "lei.*complementar")) {
        return("Federal")
      }
      if (str_detect(type_lower, "medida.*provisoria")) {
        return("Federal")
      }
    }
    
    # Use author information
    if (!is.na(author)) {
      author_lower <- str_to_lower(author)
      
      # Federal level
      if (str_detect(author_lower, "presidente|ministro|congresso|senado|camara.*deputados")) {
        return("Federal")
      }
      
      # State level
      if (str_detect(author_lower, "governador|assembleia.*legislativa|governo.*estado")) {
        return("Estadual")
      }
      
      # Municipal level
      if (str_detect(author_lower, "prefeito|camara.*municipal|governo.*municipal")) {
        return("Municipal")
      }
      
      # Regulatory agencies
      if (str_detect(author_lower, "antt|antaq|anac|aneel|anvisa|bacen")) {
        return("Agência Reguladora")
      }
    }
    
    return("Não Classificado")
    
  }, authors, types)
}

#' Map states to geographic regions
#' @param states Vector of state codes
#' @return Vector of region names
map_state_to_region_pipeline <- function(states) {
  
  region_mapping <- list(
    "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
    "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
    "Centro-Oeste" = c("DF", "GO", "MT", "MS"),
    "Sudeste" = c("ES", "MG", "RJ", "SP"),
    "Sul" = c("PR", "RS", "SC")
  )
  
  sapply(states, function(state) {
    if (is.na(state)) return(NA)
    
    for (region in names(region_mapping)) {
      if (state %in% region_mapping[[region]]) {
        return(region)
      }
    }
    
    if (state == "BR") return("Nacional")
    return("Não Classificado")
  })
}

#' Estimate document complexity
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param types Vector of types
#' @return Vector of complexity levels
estimate_document_complexity <- function(titles, ementas, types) {
  
  mapply(function(title, ementa, type) {
    
    complexity_score <- 0
    
    # Base complexity by type
    if (!is.na(type)) {
      type_lower <- str_to_lower(type)
      
      if (str_detect(type_lower, "constituicao|lei.*complementar")) complexity_score <- complexity_score + 4
      else if (str_detect(type_lower, "lei|medida.*provisoria")) complexity_score <- complexity_score + 3
      else if (str_detect(type_lower, "decreto")) complexity_score <- complexity_score + 2
      else complexity_score <- complexity_score + 1
    }
    
    # Text length indicators
    if (!is.na(title)) {
      title_words <- str_count(title, "\\S+")
      if (title_words > 15) complexity_score <- complexity_score + 1
    }
    
    if (!is.na(ementa)) {
      ementa_words <- str_count(ementa, "\\S+")
      if (ementa_words > 100) complexity_score <- complexity_score + 2
      else if (ementa_words > 50) complexity_score <- complexity_score + 1
    }
    
    # Technical terms indicator
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    ))
    
    technical_terms <- c("regulamenta", "institui", "disciplina", "estabelece", 
                        "procedimento", "criterio", "norma", "parametro")
    
    technical_count <- sum(sapply(technical_terms, function(term) {
      str_count(combined_text, term)
    }))
    
    complexity_score <- complexity_score + min(technical_count, 3)
    
    # Convert to categorical
    if (complexity_score <= 2) return("Baixa")
    else if (complexity_score <= 4) return("Média")
    else if (complexity_score <= 6) return("Alta")
    else return("Muito Alta")
    
  }, titles, ementas, types)
}

#' Determine legal hierarchy level
#' @param types Vector of document types
#' @return Vector of hierarchy levels
determine_legal_hierarchy <- function(types) {
  
  sapply(types, function(type) {
    if (is.na(type)) return("Não Classificado")
    
    type_lower <- str_to_lower(type)
    
    if (str_detect(type_lower, "constituicao")) return("1 - Constitucional")
    if (str_detect(type_lower, "emenda.*constitucional")) return("1 - Constitucional")
    if (str_detect(type_lower, "lei.*complementar")) return("2 - Lei Complementar")
    if (str_detect(type_lower, "lei.*ordinaria|^lei$")) return("3 - Lei Ordinária")
    if (str_detect(type_lower, "medida.*provisoria")) return("3 - Medida Provisória")
    if (str_detect(type_lower, "decreto.*lei")) return("4 - Decreto-Lei")
    if (str_detect(type_lower, "decreto")) return("5 - Decreto")
    if (str_detect(type_lower, "portaria|resolucao|instrucao")) return("6 - Ato Normativo")
    if (str_detect(type_lower, "circular|ordem.*servico|parecer")) return("7 - Ato Administrativo")
    
    return("8 - Outros")
  })
}

#' Analyze publication pattern
#' @param dates Vector of dates
#' @param types Vector of types
#' @return Vector of publication patterns
analyze_publication_pattern <- function(dates, types) {
  
  mapply(function(date, type) {
    
    if (is.na(date)) return("Data Indisponível")
    
    # Day of week pattern
    weekday <- weekdays(date)
    
    # Month pattern
    month_num <- month(date)
    
    # End of year rush
    if (month_num == 12) return("Fim de Ano")
    
    # Beginning of year
    if (month_num <= 2) return("Início de Ano")
    
    # Legislative calendar
    if (month_num >= 7 && month_num <= 11) return("Período Legislativo Intenso")
    
    # Regular pattern
    return("Período Regular")
    
  }, dates, types)
}

#' Perform text analysis on documents
#' @param documents Documents with metadata
#' @return Documents with text analysis
perform_text_analysis <- function(documents) {
  
  log_event("Performing text analysis")
  
  analyzed <- documents %>%
    mutate(
      # Language detection
      idioma_detectado = detect_document_language(titulo, ementa),
      
      # Sentiment indicators (basic)
      tom_documento = analyze_document_tone(titulo, ementa),
      
      # Key terms extraction
      termos_chave = extract_key_terms(titulo, ementa),
      
      # Text readability
      legibilidade = assess_text_readability(ementa),
      
      # Document scope
      abrangencia = determine_document_scope(titulo, ementa, estado)
    )
  
  return(analyzed)
}

#' Detect document language
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @return Vector of detected languages
detect_document_language <- function(titles, ementas) {
  
  mapply(function(title, ementa) {
    
    # Combine text for analysis
    combined_text <- paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    )
    
    if (nchar(str_trim(combined_text)) < 10) {
      return("Texto insuficiente")
    }
    
    # Simple Portuguese detection
    portuguese_indicators <- c("de", "da", "do", "para", "com", "em", "por", "que", "são", "uma")
    
    text_lower <- str_to_lower(combined_text)
    portuguese_count <- sum(sapply(portuguese_indicators, function(word) {
      str_count(text_lower, paste0("\\b", word, "\\b"))
    }))
    
    if (portuguese_count >= 3) {
      return("Português")
    }
    
    # Use textcat if available
    if (requireNamespace("textcat", quietly = TRUE)) {
      tryCatch({
        detected <- textcat::textcat(combined_text)
        return(ifelse(detected == "portuguese", "Português", "Outro"))
      }, error = function(e) {
        return("Não Detectado")
      })
    }
    
    return("Não Detectado")
    
  }, titles, ementas)
}

#' Analyze document tone
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @return Vector of document tones
analyze_document_tone <- function(titles, ementas) {
  
  mapply(function(title, ementa) {
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    ))
    
    # Regulatory tone
    regulatory_terms <- c("regulamenta", "disciplina", "estabelece", "determina", "proibe")
    if (any(sapply(regulatory_terms, function(term) str_detect(combined_text, term)))) {
      return("Regulatório")
    }
    
    # Promotional tone
    promotional_terms <- c("promove", "incentiva", "fomenta", "desenvolve", "melhora")
    if (any(sapply(promotional_terms, function(term) str_detect(combined_text, term)))) {
      return("Promocional")
    }
    
    # Emergency tone
    emergency_terms <- c("urgente", "emergencia", "medida.*urgente", "situacao.*critica")
    if (any(sapply(emergency_terms, function(term) str_detect(combined_text, term)))) {
      return("Emergencial")
    }
    
    return("Neutro")
    
  }, titles, ementas)
}

#' Extract key terms from documents
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @return Vector of key terms (comma-separated)
extract_key_terms <- function(titles, ementas) {
  
  mapply(function(title, ementa) {
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    ))
    
    # Transport-related terms
    transport_terms <- c("transporte", "mobilidade", "trânsito", "viário", "ônibus", 
                        "metro", "trem", "bicicleta", "pedestre", "estacionamento")
    
    found_terms <- transport_terms[sapply(transport_terms, function(term) {
      str_detect(combined_text, term)
    })]
    
    if (length(found_terms) > 0) {
      return(paste(head(found_terms, 5), collapse = ", "))
    }
    
    return("Termos não identificados")
    
  }, titles, ementas)
}

#' Assess text readability
#' @param ementas Vector of summaries
#' @return Vector of readability levels
assess_text_readability <- function(ementas) {
  
  sapply(ementas, function(ementa) {
    
    if (is.na(ementa) || nchar(str_trim(ementa)) < 20) {
      return("Texto insuficiente")
    }
    
    # Simple readability assessment
    word_count <- str_count(ementa, "\\S+")
    sentence_count <- str_count(ementa, "[.!?]+")
    
    if (sentence_count == 0) sentence_count <- 1
    
    avg_words_per_sentence <- word_count / sentence_count
    
    # Simple classification
    if (avg_words_per_sentence <= 15) return("Simples")
    else if (avg_words_per_sentence <= 25) return("Moderado")
    else return("Complexo")
  })
}

#' Determine document scope
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param states Vector of states
#' @return Vector of scope classifications
determine_document_scope <- function(titles, ementas, states) {
  
  mapply(function(title, ementa, state) {
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    ))
    
    # Geographic scope indicators
    if (str_detect(combined_text, "nacional|territorio.*nacional|todo.*pais")) {
      return("Nacional")
    }
    
    if (!is.na(state)) {
      if (state == "BR") return("Nacional")
      if (state == "DF") return("Distrito Federal")
      return("Estadual/Municipal")
    }
    
    # Sectoral scope
    if (str_detect(combined_text, "setor|categoria|classe|grupo")) {
      return("Setorial")
    }
    
    return("Geral")
    
  }, titles, ementas, states)
}

#' Classify documents by subject
#' @param documents Documents with text analysis
#' @return Documents with classification
classify_documents <- function(documents) {
  
  log_event("Classifying documents by subject")
  
  classified <- documents %>%
    mutate(
      # Primary classification
      categoria_primaria = classify_primary_category(titulo, ementa, tipo),
      
      # Secondary classification
      categoria_secundaria = classify_secondary_category(titulo, ementa),
      
      # Transport relevance score
      relevancia_transporte = calculate_transport_relevance_pipeline(titulo, ementa),
      
      # Legal nature
      natureza_juridica = classify_legal_nature(tipo, titulo, ementa),
      
      # Implementation complexity
      complexidade_implementacao = assess_implementation_complexity(titulo, ementa, tipo)
    )
  
  return(classified)
}

#' Classify primary category
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param types Vector of types
#' @return Vector of primary categories
classify_primary_category <- function(titles, ementas, types) {
  
  mapply(function(title, ementa, type) {
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, ""),
      coalesce(type, "")
    ))
    
    # Transport and mobility
    if (str_detect(combined_text, "transport|mobilidad|trânsit|ônibus|metro|trem|viário|rodoviário")) {
      return("Transporte e Mobilidade")
    }
    
    # Urban planning
    if (str_detect(combined_text, "urbano|planejamento|zoneamento|uso.*solo|ocupação")) {
      return("Planejamento Urbano")
    }
    
    # Environment
    if (str_detect(combined_text, "ambiente|ambiental|sustentavel|ecológico|poluição")) {
      return("Meio Ambiente")
    }
    
    # Infrastructure
    if (str_detect(combined_text, "infraestrutura|obra.*publica|saneamento|energia")) {
      return("Infraestrutura")
    }
    
    # Administrative
    if (str_detect(combined_text, "administrativ|gestão|procedimento|servidor.*público")) {
      return("Administrativo")
    }
    
    # Financial
    if (str_detect(combined_text, "orçament|financeiro|tributário|fiscal|imposto")) {
      return("Financeiro")
    }
    
    return("Outros")
    
  }, titles, ementas, types)
}

#' Classify secondary category
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @return Vector of secondary categories
classify_secondary_category <- function(titles, ementas) {
  
  mapply(function(title, ementa) {
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    ))
    
    # Specific transport subcategories
    if (str_detect(combined_text, "transporte.*público|transporte.*coletivo")) {
      return("Transporte Público")
    }
    
    if (str_detect(combined_text, "bicicleta|ciclovia|ciclofaixa")) {
      return("Mobilidade Ativa")
    }
    
    if (str_detect(combined_text, "estacionamento|zona.*azul")) {
      return("Estacionamento")
    }
    
    if (str_detect(combined_text, "sinalização|semáforo|trânsito")) {
      return("Sinalização e Trânsito")
    }
    
    if (str_detect(combined_text, "acessibilidade|pessoa.*deficiência")) {
      return("Acessibilidade")
    }
    
    return("Geral")
    
  }, titles, ementas)
}

#' Calculate transport relevance for pipeline
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @return Vector of relevance scores (0-100)
calculate_transport_relevance_pipeline <- function(titles, ementas) {
  
  mapply(function(title, ementa) {
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    ))
    
    score <- 0
    
    # High relevance terms (15 points each)
    high_terms <- c("transporte público", "mobilidade urbana", "sistema viário")
    score <- score + sum(str_count(combined_text, high_terms)) * 15
    
    # Medium relevance terms (8 points each)
    medium_terms <- c("ônibus", "metrô", "trem", "brt", "vlt", "ciclovia")
    score <- score + sum(str_count(combined_text, medium_terms)) * 8
    
    # General terms (3 points each)
    general_terms <- c("transport", "mobilidad", "trânsit", "viário", "estacionamento")
    score <- score + sum(str_count(combined_text, general_terms)) * 3
    
    return(min(score, 100))
    
  }, titles, ementas)
}

#' Classify legal nature
#' @param types Vector of types
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @return Vector of legal natures
classify_legal_nature <- function(types, titles, ementas) {
  
  mapply(function(type, title, ementa) {
    
    if (!is.na(type)) {
      type_lower <- str_to_lower(type)
      
      if (str_detect(type_lower, "lei")) return("Normativo")
      if (str_detect(type_lower, "decreto")) return("Regulamentar")
      if (str_detect(type_lower, "portaria|resolução")) return("Administrativo")
      if (str_detect(type_lower, "parecer")) return("Consultivo")
    }
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, "")
    ))
    
    if (str_detect(combined_text, "regulamenta|disciplina")) return("Regulamentar")
    if (str_detect(combined_text, "institui|cria")) return("Constitutivo")
    if (str_detect(combined_text, "altera|modifica")) return("Modificativo")
    if (str_detect(combined_text, "revoga|extingue")) return("Extintivo")
    
    return("Geral")
    
  }, types, titles, ementas)
}

#' Assess implementation complexity
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param types Vector of types
#' @return Vector of complexity assessments
assess_implementation_complexity <- function(titles, ementas, types) {
  
  mapply(function(title, ementa, type) {
    
    complexity_indicators <- 0
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, ""),
      coalesce(type, "")
    ))
    
    # Regulatory complexity
    if (str_detect(combined_text, "regulamento|procedimento|critério")) complexity_indicators <- complexity_indicators + 1
    
    # Multiple stakeholders
    if (str_detect(combined_text, "coordenação|articulação|integração")) complexity_indicators <- complexity_indicators + 1
    
    # Technical requirements
    if (str_detect(combined_text, "especificação|norma.*técnica|padrão")) complexity_indicators <- complexity_indicators + 1
    
    # Financial implications
    if (str_detect(combined_text, "orçamento|recurso|financiamento")) complexity_indicators <- complexity_indicators + 1
    
    # Implementation timeline
    if (str_detect(combined_text, "prazo|cronograma|etapa")) complexity_indicators <- complexity_indicators + 1
    
    if (complexity_indicators <= 1) return("Baixa")
    else if (complexity_indicators <= 3) return("Média")
    else return("Alta")
    
  }, titles, ementas, types)
}

#' Score document quality
#' @param documents Classified documents
#' @return Documents with quality scores
score_document_quality <- function(documents) {
  
  log_event("Scoring document quality")
  
  scored <- documents %>%
    mutate(
      quality_score = calculate_quality_score(
        titulo, ementa, data, numero, tipo, url, autor
      ),
      quality_category = categorize_quality_score(quality_score),
      quality_issues = identify_quality_issues(
        titulo, ementa, data, numero, tipo, url
      )
    )
  
  return(scored)
}

#' Calculate overall quality score
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param dates Vector of dates
#' @param numbers Vector of numbers
#' @param types Vector of types
#' @param urls Vector of URLs
#' @param authors Vector of authors
#' @return Vector of quality scores (0-100)
calculate_quality_score <- function(titles, ementas, dates, numbers, types, urls, authors) {
  
  mapply(function(title, ementa, date, number, type, url, author) {
    
    score <- 0
    
    # Title quality (25 points)
    if (!is.na(title) && nchar(str_trim(title)) >= 10) {
      score <- score + 20
      if (nchar(title) >= 30) score <- score + 5
    }
    
    # Ementa quality (25 points)
    if (!is.na(ementa) && nchar(str_trim(ementa)) >= 20) {
      score <- score + 15
      if (nchar(ementa) >= 50) score <- score + 5
      if (nchar(ementa) >= 100) score <- score + 5
    }
    
    # Date quality (15 points)
    if (!is.na(date)) {
      score <- score + 10
      if (date >= as.Date("1988-10-05")) score <- score + 5  # Post-Constitution
    }
    
    # Number quality (10 points)
    if (!is.na(number) && nchar(str_trim(number)) > 0) {
      score <- score + 10
    }
    
    # Type quality (10 points)
    if (!is.na(type) && nchar(str_trim(type)) > 0) {
      score <- score + 10
    }
    
    # URL quality (10 points)
    if (!is.na(url) && str_detect(url, "^https?://")) {
      score <- score + 10
    }
    
    # Author quality (5 points)
    if (!is.na(author) && nchar(str_trim(author)) > 0) {
      score <- score + 5
    }
    
    return(min(score, 100))
    
  }, titles, ementas, dates, numbers, types, urls, authors)
}

#' Categorize quality scores
#' @param scores Vector of quality scores
#' @return Vector of quality categories
categorize_quality_score <- function(scores) {
  
  sapply(scores, function(score) {
    if (is.na(score)) return("Não Avaliado")
    if (score >= 90) return("Excelente")
    if (score >= 80) return("Boa")
    if (score >= 70) return("Aceitável")
    if (score >= 50) return("Baixa")
    return("Muito Baixa")
  })
}

#' Identify quality issues
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param dates Vector of dates
#' @param numbers Vector of numbers
#' @param types Vector of types
#' @param urls Vector of URLs
#' @return Vector of quality issues (comma-separated)
identify_quality_issues <- function(titles, ementas, dates, numbers, types, urls) {
  
  mapply(function(title, ementa, date, number, type, url) {
    
    issues <- character(0)
    
    if (is.na(title) || nchar(str_trim(title)) < 10) {
      issues <- c(issues, "Título inadequado")
    }
    
    if (is.na(ementa) || nchar(str_trim(ementa)) < 20) {
      issues <- c(issues, "Ementa insuficiente")
    }
    
    if (is.na(date)) {
      issues <- c(issues, "Data ausente")
    } else if (date < as.Date("1500-01-01") || date > Sys.Date() + 365) {
      issues <- c(issues, "Data inválida")
    }
    
    if (is.na(number) || nchar(str_trim(number)) == 0) {
      issues <- c(issues, "Número ausente")
    }
    
    if (is.na(type) || nchar(str_trim(type)) == 0) {
      issues <- c(issues, "Tipo não especificado")
    }
    
    if (!is.na(url) && !str_detect(url, "^https?://")) {
      issues <- c(issues, "URL inválida")
    }
    
    if (length(issues) == 0) {
      return("Nenhum problema identificado")
    }
    
    return(paste(issues, collapse = ", "))
    
  }, titles, ementas, dates, numbers, types, urls)
}

#' Enhance document metadata (final stage)
#' @param documents Documents with quality scores
#' @return Final enhanced documents
enhance_document_metadata <- function(documents) {
  
  log_event("Final metadata enhancement")
  
  enhanced <- documents %>%
    mutate(
      # Processing metadata
      versao_processamento = "1.0",
      data_ultima_atualizacao = Sys.time(),
      
      # Document fingerprint
      documento_hash = sapply(1:nrow(.), function(i) {
        digest::digest(paste(titulo[i], numero[i], data[i]), algo = "md5")
      }),
      
      # Research indicators
      relevancia_academica = assess_academic_relevance(titulo, ementa, tipo),
      potencial_citacao = assess_citation_potential(titulo, ementa, tipo, data),
      
      # Processing flags
      requer_revisao = quality_score < 70,
      documento_completo = !is.na(titulo) & !is.na(ementa) & !is.na(data),
      pronto_para_analise = quality_score >= 70 & documento_completo
    )
  
  return(enhanced)
}

#' Assess academic relevance
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param types Vector of types
#' @return Vector of academic relevance scores
assess_academic_relevance <- function(titles, ementas, types) {
  
  mapply(function(title, ementa, type) {
    
    relevance <- 0
    
    combined_text <- str_to_lower(paste(
      coalesce(title, ""),
      coalesce(ementa, ""),
      coalesce(type, "")
    ))
    
    # Research-relevant terms
    academic_terms <- c("pesquisa", "estudo", "análise", "avaliação", "política pública")
    relevance <- relevance + sum(str_count(combined_text, academic_terms)) * 2
    
    # Transport research relevance
    if (str_detect(combined_text, "transport|mobilidad")) relevance <- relevance + 3
    
    # Innovation indicators
    innovation_terms <- c("inovação", "tecnologia", "sustentável", "inteligente")
    relevance <- relevance + sum(str_count(combined_text, innovation_terms))
    
    return(min(relevance, 10))
    
  }, titles, ementas, types)
}

#' Assess citation potential
#' @param titles Vector of titles
#' @param ementas Vector of summaries
#' @param types Vector of types
#' @param dates Vector of dates
#' @return Vector of citation potential scores
assess_citation_potential <- function(titles, ementas, types, dates) {
  
  mapply(function(title, ementa, type, date) {
    
    potential <- 0
    
    # Document importance by type
    if (!is.na(type)) {
      type_lower <- str_to_lower(type)
      if (str_detect(type_lower, "lei")) potential <- potential + 3
      if (str_detect(type_lower, "decreto")) potential <- potential + 2
      if (str_detect(type_lower, "resolução")) potential <- potential + 1
    }
    
    # Recency factor
    if (!is.na(date)) {
      years_old <- as.numeric(Sys.Date() - date) / 365
      if (years_old <= 5) potential <- potential + 2
      else if (years_old <= 10) potential <- potential + 1
    }
    
    # Content richness
    if (!is.na(ementa) && nchar(ementa) > 100) potential <- potential + 1
    
    return(min(potential, 8))
    
  }, titles, ementas, types, dates)
}

#' Apply quality filters to final results
#' @param documents Processed documents
#' @param options Processing options
#' @return Quality-filtered documents
apply_quality_filters <- function(documents, options) {
  
  if (is.null(documents) || nrow(documents) == 0) {
    return(documents)
  }
  
  min_quality <- options$min_document_quality
  
  # Apply quality filter
  quality_filtered <- documents %>%
    filter(quality_score >= min_quality)
  
  log_event(paste("Quality filter applied: retained", nrow(quality_filtered), 
                 "of", nrow(documents), "documents"))
  
  return(quality_filtered)
}

#' Helper function for row numbering
seq_nrow <- function(data) {
  seq_len(nrow(data))
}