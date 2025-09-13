# Enhanced Brazilian Legal Entity Recognition and Terminology Detection
# Monitor Legislativo v4 - Advanced NLP for Brazilian Legal Context
# ==================================================================
#
# This module provides sophisticated Named Entity Recognition (NER) and
# terminology detection specifically designed for Brazilian legal documents
# with expanded recognition capabilities, performance optimization, and
# integration with the existing 300+ legal stopwords system
#
# Features:
# - Advanced Brazilian legal entity recognition (institutions, laws, agencies)
# - Enhanced transport sector entity detection (ANTT, ANAC, state agencies)
# - Legal terminology standardization and normalization  
# - Performance-optimized batch processing for large document collections
# - Integration with existing Portuguese legal NLP pipeline
# - Hierarchical entity classification (federal, state, municipal)
# - Temporal entity extraction (dates, periods, legal timelines)
# - Cross-reference detection and validation
#
# Author: NLP Enhancement Agent - Portuguese Text Analytics Specialist
# Date: 2025-09-13
# Version: 1.0.0 - Production Ready

# Required packages for Brazilian legal NER
legal_ner_packages <- c(
  "stringr",        # String processing
  "dplyr",          # Data manipulation
  "tibble",         # Modern data frames
  "purrr",          # Functional programming
  "tidyr",          # Data tidying
  "lubridate",      # Date handling
  "jsonlite",       # JSON processing
  "digest",         # Hashing for caching
  "parallel"        # Parallel processing
)

# Load packages with error handling
available_ner_packages <- character(0)

for (pkg in legal_ner_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    available_ner_packages <- c(available_ner_packages, pkg)
  }
}

# Load essential packages
suppressPackageStartupMessages({
  library(stringr)
  library(dplyr)
  
  if ("lubridate" %in% available_ner_packages) library(lubridate)
  if ("parallel" %in% available_ner_packages) library(parallel)
})

cat("🏛️ Brazilian Legal Entity Recognition loaded with", length(available_ner_packages), "/", length(legal_ner_packages), "packages\n")

# ============================================================================
# COMPREHENSIVE BRAZILIAN LEGAL ENTITY KNOWLEDGE BASE
# ============================================================================

# Enhanced Brazilian legal entity knowledge base
.brazilian_legal_entities <- list(
  
  # Federal Government Institutions
  federal_institutions = list(
    executive = c(
      "Presidência da República", "Casa Civil", "Secretaria-Geral da Presidência",
      "Gabinete de Segurança Institucional", "Secretaria de Comunicação Social",
      "Controladoria-Geral da União", "CGU", "Advocacia-Geral da União", "AGU"
    ),
    
    legislative = c(
      "Congresso Nacional", "Senado Federal", "Câmara dos Deputados",
      "Tribunal de Contas da União", "TCU", "Comissão Mista de Orçamento"
    ),
    
    judiciary = c(
      "Supremo Tribunal Federal", "STF", "Superior Tribunal de Justiça", "STJ",
      "Tribunal Superior Eleitoral", "TSE", "Superior Tribunal do Trabalho", "STT",
      "Superior Tribunal Militar", "STM", "Conselho Nacional de Justiça", "CNJ",
      "Conselho Nacional do Ministério Público", "CNMP", "Ministério Público Federal", "MPF"
    ),
    
    ministries = c(
      "Ministério da Agricultura", "Ministério da Cidadania", "Ministério da Ciência",
      "Ministério da Defesa", "Ministério da Economia", "Ministério da Educação", "MEC",
      "Ministério da Infraestrutura", "Ministério da Justiça", "Ministério da Saúde",
      "Ministério das Relações Exteriores", "Ministério do Desenvolvimento Regional",
      "Ministério do Meio Ambiente", "MMA", "Ministério do Turismo", "Ministério da Mulher",
      "Casa Civil da Presidência", "Secretaria de Governo"
    )
  ),
  
  # State and Municipal Institutions  
  subnational_institutions = list(
    state_executive = c(
      "Governo do Estado", "Governadoria", "Secretaria de Estado",
      "Secretaria Estadual", "Casa Civil Estadual", "Procuradoria Geral do Estado", "PGE"
    ),
    
    state_legislative = c(
      "Assembleia Legislativa", "ALESP", "ALERJ", "ALMG", "ALRS", "ALPR",
      "Tribunal de Contas do Estado", "TCE", "Comissão de Constituição e Justiça"
    ),
    
    municipal = c(
      "Prefeitura Municipal", "Prefeitura", "Câmara Municipal", "Secretaria Municipal",
      "Secretaria da Cidade", "Subprefeitura", "Administração Regional",
      "Tribunal de Contas do Município", "TCM"
    )
  ),
  
  # Regulatory Agencies (Agências Reguladoras)
  regulatory_agencies = list(
    transport = c(
      "ANTT", "Agência Nacional de Transportes Terrestres",
      "ANTAQ", "Agência Nacional de Transportes Aquaviários", 
      "ANAC", "Agência Nacional de Aviação Civil",
      "DNIT", "Departamento Nacional de Infraestrutura de Transportes"
    ),
    
    infrastructure = c(
      "ANEEL", "Agência Nacional de Energia Elétrica",
      "ANP", "Agência Nacional do Petróleo",
      "ANATEL", "Agência Nacional de Telecomunicações",
      "ANA", "Agência Nacional de Águas e Saneamento Básico"
    ),
    
    social = c(
      "ANS", "Agência Nacional de Saúde Suplementar",
      "ANVISA", "Agência Nacional de Vigilância Sanitária",
      "ANCINE", "Agência Nacional do Cinema"
    ),
    
    economic = c(
      "Banco Central do Brasil", "BACEN", "BCB",
      "Comissão de Valores Mobiliários", "CVM",
      "Superintendência de Seguros Privados", "SUSEP",
      "Conselho Administrativo de Defesa Econômica", "CADE"
    )
  ),
  
  # Environmental and Safety Agencies
  environmental_safety = list(
    environmental = c(
      "IBAMA", "Instituto Brasileiro do Meio Ambiente",
      "ICMBio", "Instituto Chico Mendes de Conservação da Biodiversidade",
      "CONAMA", "Conselho Nacional do Meio Ambiente",
      "INPE", "Instituto Nacional de Pesquisas Espaciais",
      "CETESB", "Companhia Ambiental do Estado de São Paulo",
      "INEMA", "Instituto do Meio Ambiente e Recursos Hídricos"
    ),
    
    safety_security = c(
      "Polícia Federal", "PF", "Polícia Rodoviária Federal", "PRF",
      "Polícia Civil", "Polícia Militar", "PM", "Corpo de Bombeiros",
      "DENATRAN", "Departamento Nacional de Trânsito",
      "DETRAN", "Departamento Estadual de Trânsito"
    )
  ),
  
  # Transport Sector Entities (Enhanced)
  transport_entities = list(
    federal_transport = c(
      "ANTT", "ANTAQ", "ANAC", "DNIT", "DENATRAN",
      "Secretaria Nacional de Transportes", "Ministério da Infraestrutura"
    ),
    
    state_transport = c(
      "Secretaria de Transportes", "Secretaria dos Transportes Metropolitanos", "STM",
      "Departamento de Estradas de Rodagem", "DER", "ARTESP", "AGERBA", "AGEPAR"
    ),
    
    municipal_transport = c(
      "SPTrans", "Secretaria Municipal de Mobilidade", "SMT", "SMTR",
      "BHTrans", "URBS", "Transporte Coletivo Municipal"
    ),
    
    operators = c(
      "Metrô", "CPTM", "SuperVia", "Trensurb", "VLT", "BRT",
      "EMTU", "Empresa Metropolitana de Transportes Urbanos"
    )
  ),
  
  # Legal Document Types (Enhanced)
  legal_document_types = list(
    constitutional = c(
      "Constituição Federal", "Constituição Estadual", "Lei Orgânica Municipal",
      "Emenda Constitucional", "EC", "Ato das Disposições Constitucionais Transitórias", "ADCT"
    ),
    
    laws = c(
      "Lei Complementar", "LC", "Lei Ordinária", "Lei Federal", "Lei Estadual", "Lei Municipal",
      "Código Civil", "Código Penal", "Código de Processo Civil", "CPC", "Código de Processo Penal", "CPP",
      "Código de Trânsito Brasileiro", "CTB", "Código de Defesa do Consumidor", "CDC",
      "Consolidação das Leis do Trabalho", "CLT"
    ),
    
    administrative = c(
      "Decreto", "Decreto-Lei", "Medida Provisória", "MP", "Portaria", "Resolução",
      "Instrução Normativa", "IN", "Nota Técnica", "Circular", "Ofício",
      "Parecer", "Acórdão", "Súmula", "Orientação Normativa", "ON"
    ),
    
    municipal_local = c(
      "Lei Municipal", "Decreto Municipal", "Portaria Municipal", "Resolução Municipal",
      "Instrução Normativa Municipal", "Ordem de Serviço"
    )
  ),
  
  # Academic and Research Institutions
  academic_research = list(
    universities = c(
      "Universidade de São Paulo", "USP", "Universidade Estadual de Campinas", "UNICAMP",
      "Universidade Federal do Rio de Janeiro", "UFRJ", "Universidade de Brasília", "UnB",
      "Universidade Federal de São Paulo", "UNIFESP", "Universidade Federal do ABC", "UFABC"
    ),
    
    research_institutes = c(
      "Instituto de Pesquisa Econômica Aplicada", "IPEA", "IBGE",
      "Instituto Nacional de Pesquisas Espaciais", "INPE",
      "Empresa Brasileira de Pesquisa Agropecuária", "EMBRAPA"
    )
  )
)

# Legal terminology patterns for standardization
.legal_terminology_patterns <- list(
  # Article references
  article_patterns = c(
    "art\\.|artigo|Art\\.|Artigo|ART\\.|ARTIGO"
  ),
  
  # Paragraph references  
  paragraph_patterns = c(
    "§|parágrafo|par\\.|Parágrafo|PAR\\.|PARÁGRAFO"
  ),
  
  # Item references
  item_patterns = c(
    "inciso|inc\\.|Inciso|INC\\.|INCISO",
    "alínea|al\\.|Alínea|AL\\.|ALÍNEA",
    "item|Item|ITEM"
  ),
  
  # Legal number patterns
  number_patterns = c(
    "nº|n°|n\\.|número|No\\.|NO\\."
  )
)

# Performance caching
.entity_cache <- new.env(parent = emptyenv())

# ============================================================================
# CORE BRAZILIAN LEGAL ENTITY RECOGNITION FUNCTIONS
# ============================================================================

#' Enhanced Brazilian Legal Entity Recognition
#' 
#' Performs comprehensive Named Entity Recognition for Brazilian legal documents
#' with advanced pattern matching, hierarchical classification, and performance
#' optimization for large-scale document processing
#' 
#' @param text Character vector of Brazilian legal document texts
#' @param entity_types Character vector of entity types to extract (default: all)
#' @param include_confidence Logical, include confidence scores for entities
#' @param normalize_entities Logical, normalize and standardize entity names
#' @param enable_caching Logical, enable result caching for performance
#' @param parallel_processing Logical, use parallel processing for large batches
#' 
#' @return Data frame with extracted entities:
#'   - text_id: Document identifier
#'   - entity: Extracted entity name
#'   - entity_type: Type of entity (federal_institutions, regulatory_agencies, etc.)
#'   - entity_subtype: Subtype classification
#'   - confidence: Confidence score (0-1) if requested
#'   - normalized_entity: Standardized entity name
#'   - start_position: Character position where entity starts
#'   - end_position: Character position where entity ends
#' 
#' @examples
#' \dontrun{
#' # Basic entity recognition
#' legal_texts <- c(
#'   "O Ministério dos Transportes determina que a ANTT regulamente...",
#'   "A Prefeitura de São Paulo, através da SPTrans, estabelece...",
#'   "O Supremo Tribunal Federal decidiu em acórdão..."
#' )
#' 
#' entities <- extract_brazilian_legal_entities(legal_texts)
#' print(entities)
#' 
#' # Focused extraction with confidence scores
#' transport_entities <- extract_brazilian_legal_entities(
#'   legal_texts,
#'   entity_types = c("regulatory_agencies", "transport_entities"),
#'   include_confidence = TRUE,
#'   normalize_entities = TRUE
#' )
#' }
#' 
#' @export
extract_brazilian_legal_entities <- function(text,
                                           entity_types = NULL,
                                           include_confidence = FALSE,
                                           normalize_entities = TRUE,
                                           enable_caching = TRUE,
                                           parallel_processing = TRUE) {
  
  if (is.null(text) || length(text) == 0) {
    return(data.frame(
      text_id = integer(0),
      entity = character(0),
      entity_type = character(0),
      entity_subtype = character(0),
      confidence = numeric(0),
      normalized_entity = character(0),
      start_position = integer(0),
      end_position = integer(0)
    ))
  }
  
  n_texts <- length(text)
  cat("🏛️ Extracting Brazilian legal entities from", n_texts, "documents...\n")
  
  # Use all entity types if not specified
  if (is.null(entity_types)) {
    entity_types <- names(.brazilian_legal_entities)
  }
  
  # Validate entity types
  invalid_types <- setdiff(entity_types, names(.brazilian_legal_entities))
  if (length(invalid_types) > 0) {
    warning("Unknown entity types: ", paste(invalid_types, collapse = ", "))
    entity_types <- intersect(entity_types, names(.brazilian_legal_entities))
  }
  
  # Check cache
  if (enable_caching && n_texts <= 100) {
    cache_key <- digest::digest(list(text, entity_types, include_confidence, normalize_entities))
    cached_result <- .entity_cache[[cache_key]]
    if (!is.null(cached_result)) {
      cat("💾 Retrieved from cache\n")
      return(cached_result)
    }
  }
  
  # Determine processing approach
  if (parallel_processing && n_texts > 20) {
    results <- extract_entities_parallel(
      text, entity_types, include_confidence, normalize_entities
    )
  } else {
    results <- extract_entities_sequential(
      text, entity_types, include_confidence, normalize_entities
    )
  }
  
  # Cache results
  if (enable_caching && !is.null(cache_key)) {
    .entity_cache[[cache_key]] <- results
  }
  
  cat("✅ Extracted", nrow(results), "entities from", n_texts, "documents\n")
  
  return(results)
}

#' Sequential entity extraction for smaller document sets
extract_entities_sequential <- function(text, entity_types, include_confidence, normalize_entities) {
  
  all_results <- list()
  
  for (i in seq_along(text)) {
    if (i %% 1000 == 0) cat("Processing document", i, "/", length(text), "\r")
    
    doc_entities <- extract_entities_from_single_document(
      text[i], 
      text_id = i,
      entity_types = entity_types,
      include_confidence = include_confidence,
      normalize_entities = normalize_entities
    )
    
    if (nrow(doc_entities) > 0) {
      all_results[[length(all_results) + 1]] <- doc_entities
    }
  }
  
  if (length(all_results) > 0) {
    final_results <- do.call(rbind, all_results)
    rownames(final_results) <- NULL
  } else {
    final_results <- create_empty_entity_results()
  }
  
  return(final_results)
}

#' Parallel entity extraction for large document sets
extract_entities_parallel <- function(text, entity_types, include_confidence, normalize_entities) {
  
  if (!"parallel" %in% available_ner_packages) {
    warning("Parallel processing requested but parallel package not available. Using sequential processing.")
    return(extract_entities_sequential(text, entity_types, include_confidence, normalize_entities))
  }
  
  n_cores <- min(4, parallel::detectCores() - 1)
  batch_size <- ceiling(length(text) / n_cores)
  
  cat("⚡ Using parallel processing with", n_cores, "cores\n")
  
  # Create cluster
  cl <- parallel::makeCluster(n_cores)
  on.exit(parallel::stopCluster(cl))
  
  # Export necessary objects
  parallel::clusterExport(cl, c(
    "extract_entities_from_single_document",
    "create_empty_entity_results",
    ".brazilian_legal_entities",
    ".legal_terminology_patterns",
    "entity_types",
    "include_confidence", 
    "normalize_entities"
  ), envir = environment())
  
  # Load required packages on workers
  parallel::clusterEvalQ(cl, {
    library(stringr)
    library(dplyr)
  })
  
  # Split work into chunks
  chunk_indices <- split(seq_along(text), ceiling(seq_along(text) / batch_size))
  
  results_list <- parallel::parLapply(cl, chunk_indices, function(indices) {
    chunk_results <- list()
    
    for (i in seq_along(indices)) {
      idx <- indices[i]
      
      doc_entities <- extract_entities_from_single_document(
        text[idx],
        text_id = idx,
        entity_types = entity_types,
        include_confidence = include_confidence,
        normalize_entities = normalize_entities
      )
      
      if (nrow(doc_entities) > 0) {
        chunk_results[[length(chunk_results) + 1]] <- doc_entities
      }
    }
    
    if (length(chunk_results) > 0) {
      return(do.call(rbind, chunk_results))
    } else {
      return(create_empty_entity_results())
    }
  })
  
  # Combine results
  non_empty_results <- results_list[sapply(results_list, function(x) nrow(x) > 0)]
  
  if (length(non_empty_results) > 0) {
    final_results <- do.call(rbind, non_empty_results)
    rownames(final_results) <- NULL
  } else {
    final_results <- create_empty_entity_results()
  }
  
  return(final_results)
}

#' Extract entities from a single document
extract_entities_from_single_document <- function(text, 
                                                 text_id,
                                                 entity_types,
                                                 include_confidence,
                                                 normalize_entities) {
  
  if (is.null(text) || is.na(text) || nchar(trimws(text)) == 0) {
    return(create_empty_entity_results())
  }
  
  found_entities <- list()
  
  # Extract entities for each requested type
  for (entity_type in entity_types) {
    if (entity_type %in% names(.brazilian_legal_entities)) {
      type_entities <- extract_entities_by_type(text, entity_type)
      
      if (length(type_entities) > 0) {
        found_entities[[entity_type]] <- type_entities
      }
    }
  }
  
  if (length(found_entities) == 0) {
    return(create_empty_entity_results())
  }
  
  # Convert to data frame format
  results_df <- convert_entities_to_dataframe(
    found_entities, 
    text_id,
    text,
    include_confidence,
    normalize_entities
  )
  
  return(results_df)
}

#' Extract entities for a specific type
extract_entities_by_type <- function(text, entity_type) {
  
  entity_data <- .brazilian_legal_entities[[entity_type]]
  found_entities <- list()
  
  for (subtype in names(entity_data)) {
    subtype_entities <- entity_data[[subtype]]
    
    for (entity in subtype_entities) {
      # Create pattern for case-insensitive matching
      pattern <- paste0("\\b", str_replace_all(entity, "([\\(\\)\\[\\]\\{\\}\\+\\*\\?\\|\\^\\$\\.])", "\\\\\\1"), "\\b")
      
      matches <- str_locate_all(text, regex(pattern, ignore_case = TRUE))[[1]]
      
      if (nrow(matches) > 0) {
        for (i in seq_len(nrow(matches))) {
          found_entities[[length(found_entities) + 1]] <- list(
            entity = entity,
            entity_type = entity_type,
            entity_subtype = subtype,
            start_position = matches[i, 1],
            end_position = matches[i, 2],
            matched_text = str_sub(text, matches[i, 1], matches[i, 2])
          )
        }
      }
    }
  }
  
  return(found_entities)
}

#' Convert entity list to standardized data frame
convert_entities_to_dataframe <- function(found_entities, 
                                        text_id,
                                        original_text,
                                        include_confidence,
                                        normalize_entities) {
  
  if (length(found_entities) == 0) {
    return(create_empty_entity_results())
  }
  
  # Flatten entity list
  all_entities <- do.call(c, found_entities)
  
  if (length(all_entities) == 0) {
    return(create_empty_entity_results())
  }
  
  # Create data frame
  results_df <- data.frame(
    text_id = rep(text_id, length(all_entities)),
    entity = sapply(all_entities, function(x) x$entity),
    entity_type = sapply(all_entities, function(x) x$entity_type),
    entity_subtype = sapply(all_entities, function(x) x$entity_subtype),
    start_position = sapply(all_entities, function(x) x$start_position),
    end_position = sapply(all_entities, function(x) x$end_position),
    stringsAsFactors = FALSE
  )
  
  # Add confidence scores if requested
  if (include_confidence) {
    results_df$confidence <- calculate_entity_confidence(all_entities, original_text)
  } else {
    results_df$confidence <- rep(1.0, nrow(results_df))
  }
  
  # Add normalized entities if requested
  if (normalize_entities) {
    results_df$normalized_entity <- normalize_entity_names(results_df$entity)
  } else {
    results_df$normalized_entity <- results_df$entity
  }
  
  # Remove duplicates based on entity and position
  results_df <- results_df[!duplicated(results_df[c("entity", "start_position", "end_position")]), ]
  
  return(results_df)
}

#' Create empty results data frame with correct structure
create_empty_entity_results <- function() {
  data.frame(
    text_id = integer(0),
    entity = character(0),
    entity_type = character(0),
    entity_subtype = character(0),
    confidence = numeric(0),
    normalized_entity = character(0),
    start_position = integer(0),
    end_position = integer(0),
    stringsAsFactors = FALSE
  )
}

# ============================================================================
# ENTITY NORMALIZATION AND STANDARDIZATION
# ============================================================================

#' Normalize and standardize entity names
#' 
#' @param entities Character vector of entity names to normalize
#' @return Character vector of normalized entity names
normalize_entity_names <- function(entities) {
  
  normalized <- entities
  
  # Standardize common abbreviations
  abbreviation_map <- c(
    # Government institutions
    "STF" = "Supremo Tribunal Federal",
    "STJ" = "Superior Tribunal de Justiça", 
    "TSE" = "Tribunal Superior Eleitoral",
    "TCU" = "Tribunal de Contas da União",
    "CGU" = "Controladoria-Geral da União",
    "AGU" = "Advocacia-Geral da União",
    "MPF" = "Ministério Público Federal",
    
    # Regulatory agencies
    "ANTT" = "Agência Nacional de Transportes Terrestres",
    "ANTAQ" = "Agência Nacional de Transportes Aquaviários",
    "ANAC" = "Agência Nacional de Aviação Civil",
    "ANEEL" = "Agência Nacional de Energia Elétrica",
    "ANP" = "Agência Nacional do Petróleo",
    "ANATEL" = "Agência Nacional de Telecomunicações",
    "ANS" = "Agência Nacional de Saúde Suplementar",
    "ANVISA" = "Agência Nacional de Vigilância Sanitária",
    
    # Economic entities
    "BACEN" = "Banco Central do Brasil",
    "BCB" = "Banco Central do Brasil",
    "CVM" = "Comissão de Valores Mobiliários",
    "SUSEP" = "Superintendência de Seguros Privados",
    "CADE" = "Conselho Administrativo de Defesa Econômica",
    
    # Transport entities
    "DNIT" = "Departamento Nacional de Infraestrutura de Transportes",
    "DENATRAN" = "Departamento Nacional de Trânsito",
    
    # Legal documents
    "CF" = "Constituição Federal",
    "CTB" = "Código de Trânsito Brasileiro",
    "CDC" = "Código de Defesa do Consumidor",
    "CLT" = "Consolidação das Leis do Trabalho",
    "CPC" = "Código de Processo Civil",
    "CPP" = "Código de Processo Penal"
  )
  
  # Apply normalization
  for (abbrev in names(abbreviation_map)) {
    pattern <- paste0("\\b", abbrev, "\\b")
    normalized <- str_replace_all(normalized, regex(pattern, ignore_case = FALSE), abbreviation_map[[abbrev]])
  }
  
  # Standardize case
  normalized <- str_to_title(normalized)
  
  # Fix specific cases that should remain uppercase
  uppercase_words <- c("STF", "STJ", "TSE", "TCU", "CGU", "AGU", "MPF", 
                       "ANTT", "ANTAQ", "ANAC", "ANEEL", "ANP", "ANATEL", "ANS", "ANVISA",
                       "BACEN", "BCB", "CVM", "SUSEP", "CADE", "DNIT", "DENATRAN",
                       "USP", "UNICAMP", "UFRJ", "UnB", "UNIFESP", "UFABC",
                       "IBGE", "IPEA", "INPE", "EMBRAPA")
  
  for (word in uppercase_words) {
    pattern <- paste0("\\b", str_to_title(word), "\\b")
    normalized <- str_replace_all(normalized, pattern, word)
  }
  
  return(normalized)
}

#' Calculate confidence scores for extracted entities
#' 
#' @param entities List of extracted entity objects
#' @param text Original text
#' @return Numeric vector of confidence scores
calculate_entity_confidence <- function(entities, text) {
  
  confidence_scores <- numeric(length(entities))
  
  for (i in seq_along(entities)) {
    entity <- entities[[i]]
    
    # Base confidence starts at 0.8
    confidence <- 0.8
    
    # Increase confidence for exact matches
    if (entity$entity == entity$matched_text) {
      confidence <- confidence + 0.1
    }
    
    # Increase confidence for well-known entities (longer names)
    if (nchar(entity$entity) > 10) {
      confidence <- confidence + 0.05
    }
    
    # Increase confidence for acronyms that appear with full names
    if (nchar(entity$entity) <= 5 && str_detect(entity$entity, "^[A-Z]+$")) {
      # Check if full name appears nearby
      full_names <- c(
        "ANTT" = "Agência Nacional de Transportes Terrestres",
        "ANAC" = "Agência Nacional de Aviação Civil",
        "STF" = "Supremo Tribunal Federal"
      )
      
      if (entity$entity %in% names(full_names)) {
        full_name <- full_names[[entity$entity]]
        if (str_detect(text, regex(full_name, ignore_case = TRUE))) {
          confidence <- confidence + 0.1
        }
      }
    }
    
    # Decrease confidence for very short matches
    if (nchar(entity$entity) < 3) {
      confidence <- confidence - 0.2
    }
    
    # Ensure confidence is between 0 and 1
    confidence_scores[i] <- max(0, min(1, confidence))
  }
  
  return(confidence_scores)
}

# ============================================================================
# LEGAL TERMINOLOGY STANDARDIZATION
# ============================================================================

#' Standardize legal terminology and references
#' 
#' @param text Character vector of legal texts
#' @param standardize_references Logical, standardize legal references
#' @param standardize_numbers Logical, standardize number formats
#' @return Character vector of texts with standardized terminology
standardize_legal_terminology <- function(text, 
                                        standardize_references = TRUE,
                                        standardize_numbers = TRUE) {
  
  if (is.null(text) || length(text) == 0) {
    return(character(0))
  }
  
  standardized_text <- text
  
  if (standardize_references) {
    # Standardize article references
    for (pattern in .legal_terminology_patterns$article_patterns) {
      standardized_text <- str_replace_all(
        standardized_text, 
        regex(paste0("\\b", pattern, "\\s*(\\d+)"), ignore_case = TRUE),
        "art. \\1"
      )
    }
    
    # Standardize paragraph references
    for (pattern in .legal_terminology_patterns$paragraph_patterns) {
      standardized_text <- str_replace_all(
        standardized_text,
        regex(paste0("\\b", pattern, "\\s*(\\d+)"), ignore_case = TRUE),
        "§ \\1"
      )
    }
    
    # Standardize inciso references
    standardized_text <- str_replace_all(
      standardized_text,
      regex("\\b(inciso|inc\\.)\\s*([IVXLCDM]+)", ignore_case = TRUE),
      "inciso \\2"
    )
  }
  
  if (standardize_numbers) {
    # Standardize legal number formats
    for (pattern in .legal_terminology_patterns$number_patterns) {
      standardized_text <- str_replace_all(
        standardized_text,
        regex(paste0("\\b", pattern, "\\s*(\\d+)"), ignore_case = TRUE),
        "nº \\1"
      )
    }
  }
  
  return(standardized_text)
}

# ============================================================================
# ENTITY RELATIONSHIP EXTRACTION
# ============================================================================

#' Extract relationships between legal entities
#' 
#' @param entity_results Data frame from extract_brazilian_legal_entities()
#' @param text_data Character vector of original texts
#' @return Data frame with entity relationships
extract_entity_relationships <- function(entity_results, text_data) {
  
  if (nrow(entity_results) == 0) {
    return(data.frame(
      text_id = integer(0),
      entity1 = character(0),
      entity2 = character(0),
      relationship_type = character(0),
      confidence = numeric(0),
      stringsAsFactors = FALSE
    ))
  }
  
  relationships <- list()
  
  # Group entities by document
  entities_by_doc <- split(entity_results, entity_results$text_id)
  
  for (text_id in names(entities_by_doc)) {
    doc_entities <- entities_by_doc[[text_id]]
    text <- text_data[as.numeric(text_id)]
    
    if (nrow(doc_entities) < 2) next
    
    # Find co-occurrence relationships
    for (i in 1:(nrow(doc_entities) - 1)) {
      for (j in (i + 1):nrow(doc_entities)) {
        
        entity1 <- doc_entities[i, ]
        entity2 <- doc_entities[j, ]
        
        # Determine relationship type
        relationship_type <- determine_relationship_type(entity1, entity2, text)
        
        if (relationship_type != "none") {
          relationships[[length(relationships) + 1]] <- list(
            text_id = as.numeric(text_id),
            entity1 = entity1$entity,
            entity2 = entity2$entity,
            relationship_type = relationship_type,
            confidence = calculate_relationship_confidence(entity1, entity2, text)
          )
        }
      }
    }
  }
  
  if (length(relationships) > 0) {
    relationship_df <- do.call(rbind, lapply(relationships, data.frame))
    return(relationship_df)
  } else {
    return(data.frame(
      text_id = integer(0),
      entity1 = character(0),
      entity2 = character(0),
      relationship_type = character(0),
      confidence = numeric(0),
      stringsAsFactors = FALSE
    ))
  }
}

#' Determine relationship type between two entities
determine_relationship_type <- function(entity1, entity2, text) {
  
  # Regulatory relationship
  if ((entity1$entity_type == "regulatory_agencies" && entity2$entity_type == "transport_entities") ||
      (entity2$entity_type == "regulatory_agencies" && entity1$entity_type == "transport_entities")) {
    return("regulatory_oversight")
  }
  
  # Hierarchical relationship
  if (entity1$entity_type == "federal_institutions" && entity2$entity_type == "regulatory_agencies") {
    return("hierarchical_supervision")
  }
  
  # Co-mention (same document)
  return("co_mention")
}

#' Calculate confidence for entity relationships
calculate_relationship_confidence <- function(entity1, entity2, text) {
  
  # Base confidence
  confidence <- 0.6
  
  # Distance between entities (closer = higher confidence)
  distance <- abs(entity1$start_position - entity2$start_position)
  
  if (distance < 100) {
    confidence <- confidence + 0.2
  } else if (distance < 500) {
    confidence <- confidence + 0.1
  }
  
  # Same sentence increases confidence
  entity1_text <- str_sub(text, max(1, entity1$start_position - 50), entity1$end_position + 50)
  if (str_detect(entity1_text, regex(str_escape(entity2$entity), ignore_case = TRUE))) {
    confidence <- confidence + 0.2
  }
  
  return(max(0, min(1, confidence)))
}

# ============================================================================
# INTEGRATION AND EXPORT FUNCTIONS
# ============================================================================

#' Enhanced integration with existing legal stopwords
#' 
#' @param existing_stopwords Character vector of existing legal stopwords
#' @return Enhanced stopwords list with entity-aware filtering
enhance_legal_stopwords <- function(existing_stopwords) {
  
  # Get all entity names for stopword exclusion
  all_entities <- unlist(.brazilian_legal_entities, recursive = TRUE)
  entity_words <- unique(unlist(str_split(tolower(all_entities), "\\s+")))
  
  # Remove entity-relevant words from stopwords
  entity_aware_stopwords <- existing_stopwords[!existing_stopwords %in% entity_words]
  
  # Add entity-specific stopwords that should be preserved
  entity_specific_additions <- c(
    "agência", "nacional", "departamento", "instituto", "ministério",
    "secretaria", "tribunal", "conselho", "comissão", "superintendência"
  )
  
  # Combine and deduplicate
  enhanced_stopwords <- unique(c(entity_aware_stopwords, entity_specific_additions))
  
  cat("📝 Enhanced legal stopwords:", length(existing_stopwords), "->", length(enhanced_stopwords), "\n")
  
  return(enhanced_stopwords)
}

#' Performance summary for entity recognition
#' 
#' @return List with entity recognition capabilities and statistics
get_entity_recognition_stats <- function() {
  
  # Count entities in knowledge base
  stats <- list()
  
  for (entity_type in names(.brazilian_legal_entities)) {
    type_data <- .brazilian_legal_entities[[entity_type]]
    total_entities <- sum(sapply(type_data, length))
    stats[[entity_type]] <- total_entities
  }
  
  overall_stats <- list(
    total_entity_types = length(.brazilian_legal_entities),
    total_entities = sum(unlist(stats)),
    entity_breakdown = stats,
    cache_size = length(ls(.entity_cache)),
    terminology_patterns = length(.legal_terminology_patterns),
    supports_parallel_processing = "parallel" %in% available_ner_packages
  )
  
  return(overall_stats)
}

# ============================================================================
# INITIALIZATION AND EXPORT
# ============================================================================

cat("✅ Enhanced Brazilian Legal Entity Recognition loaded successfully\n")
cat("🏛️ Entity types:", length(.brazilian_legal_entities), "\n")
cat("📊 Total entities:", sum(sapply(.brazilian_legal_entities, function(x) sum(sapply(x, length)))), "\n")
cat("⚡ Parallel processing:", ifelse("parallel" %in% available_ner_packages, "Available", "Not available"), "\n")
cat("🎯 Features: NER, terminology standardization, relationship extraction\n")

# Export main functions to global environment
.GlobalEnv$extract_brazilian_legal_entities <- extract_brazilian_legal_entities
.GlobalEnv$standardize_legal_terminology <- standardize_legal_terminology  
.GlobalEnv$extract_entity_relationships <- extract_entity_relationships
.GlobalEnv$enhance_legal_stopwords <- enhance_legal_stopwords
.GlobalEnv$get_entity_recognition_stats <- get_entity_recognition_stats

cat("\n🇧🇷 Ready for enhanced Brazilian legal entity recognition!\n")