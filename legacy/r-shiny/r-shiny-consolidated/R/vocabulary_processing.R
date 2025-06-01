# SKOS Vocabulary Processing for Monitor Legislativo v4
# W3C-compliant controlled vocabularies for transport legislation

library(xml2)
library(dplyr)
library(stringr)
library(jsonlite)

# Transport vocabulary structure based on SKOS ontology
TRANSPORT_VOCABULARY <- list(
  
  # Primary concepts (broad terms)
  primary = list(
    "transporte" = list(
      prefLabel = "Transporte",
      definition = "Deslocamento de pessoas ou cargas de um local para outro",
      broader = NULL,
      narrower = c("transporte_publico", "transporte_privado", "transporte_carga"),
      related = c("mobilidade", "logistica", "infraestrutura"),
      synonyms = c("transportes", "locomoção", "deslocamento")
    ),
    
    "mobilidade" = list(
      prefLabel = "Mobilidade",
      definition = "Capacidade de deslocamento de pessoas e bens no espaço urbano",
      broader = NULL,
      narrower = c("mobilidade_urbana", "mobilidade_ativa", "mobilidade_sustentavel"),
      related = c("transporte", "acessibilidade", "planejamento_urbano"),
      synonyms = c("locomoção urbana", "deslocamento urbano")
    ),
    
    "infraestrutura" = list(
      prefLabel = "Infraestrutura de Transporte",
      definition = "Conjunto de instalações e equipamentos que viabilizam o transporte",
      broader = NULL,
      narrower = c("vias", "terminais", "sinalizacao", "equipamentos"),
      related = c("transporte", "urbanismo", "engenharia"),
      synonyms = c("infraestrutura viária", "sistema viário")
    )
  ),
  
  # Secondary concepts (specific terms)
  secondary = list(
    "transporte_publico" = list(
      prefLabel = "Transporte Público",
      definition = "Serviço de transporte coletivo disponível ao público em geral",
      broader = "transporte",
      narrower = c("onibus", "metro", "trem", "brt", "vlt"),
      related = c("mobilidade_urbana", "concessao", "tarifa"),
      synonyms = c("transporte coletivo", "transporte comum", "transporte de massa")
    ),
    
    "mobilidade_urbana" = list(
      prefLabel = "Mobilidade Urbana", 
      definition = "Condição em que se realizam os deslocamentos de pessoas no espaço urbano",
      broader = "mobilidade",
      narrower = c("transporte_urbano", "circulacao_pedestres", "ciclovias"),
      related = c("planejamento_urbano", "sustentabilidade", "acessibilidade"),
      synonyms = c("mobilidade nas cidades", "deslocamento urbano")
    ),
    
    "onibus" = list(
      prefLabel = "Ônibus",
      definition = "Veículo automotor destinado ao transporte coletivo de passageiros",
      broader = "transporte_publico",
      narrower = c("onibus_urbano", "onibus_intermunicipal", "microonibus"),
      related = c("linha_onibus", "ponto_onibus", "terminal_rodoviario"),
      synonyms = c("autocarro", "ônibus coletivo", "veículo de transporte público")
    ),
    
    "metro" = list(
      prefLabel = "Metrô",
      definition = "Sistema de transporte público urbano sobre trilhos, parcialmente subterrâneo",
      broader = "transporte_publico",
      narrower = c("linha_metro", "estacao_metro", "trem_metropolitano"),
      related = c("transporte_ferroviario", "mobilidade_urbana", "infraestrutura"),
      synonyms = c("metropolitano", "trem metropolitano", "subway")
    ),
    
    "brt" = list(
      prefLabel = "BRT - Bus Rapid Transit",
      definition = "Sistema de transporte público por ônibus com características de metro",
      broader = "transporte_publico",
      narrower = c("via_brt", "estacao_brt", "onibus_articulado"),
      related = c("onibus", "faixa_exclusiva", "mobilidade_urbana"),
      synonyms = c("ônibus de trânsito rápido", "sistema BRT", "bus rapid transit")
    )
  ),
  
  # Tertiary concepts (very specific terms)
  tertiary = list(
    "ciclovias" = list(
      prefLabel = "Ciclovias",
      definition = "Vias destinadas exclusivamente à circulação de bicicletas",
      broader = "mobilidade_urbana",
      narrower = c("ciclofaixa", "ciclorrota", "bicicletario"),
      related = c("bicicleta", "mobilidade_ativa", "sustentabilidade"),
      synonyms = c("pista de ciclismo", "via ciclável", "corredor de bicicletas")
    ),
    
    "semaforo" = list(
      prefLabel = "Semáforo",
      definition = "Equipamento de sinalização para controle de tráfego",
      broader = "sinalizacao",
      narrower = c("semaforo_veicular", "semaforo_pedestres", "semaforo_inteligente"),
      related = c("transito", "seguranca_viaria", "controle_trafego"),
      synonyms = c("sinal de trânsito", "farol de trânsito", "sinaleira")
    ),
    
    "estacionamento" = list(
      prefLabel = "Estacionamento",
      definition = "Local destinado à parada temporária de veículos",
      broader = "infraestrutura",
      narrower = c("estacionamento_publico", "estacionamento_privado", "zona_azul"),
      related = c("veiculo", "via_publica", "regulamentacao"),
      synonyms = c("parking", "área de estacionamento", "vaga de estacionamento")
    )
  )
)

#' Expand search vocabulary using SKOS relationships
#' @param query Original search query
#' @param max_terms Maximum number of terms to include
#' @param include_synonyms Whether to include synonyms
#' @return Expanded query string
expand_search_vocabulary <- function(query, max_terms = 20, include_synonyms = TRUE) {
  
  if (is.null(query) || nchar(trimws(query)) == 0) {
    return(query)
  }
  
  log_event(paste("Expanding vocabulary for query:", query))
  
  # Clean and normalize query
  normalized_query <- str_to_lower(str_trim(query))
  original_terms <- unique(str_split(normalized_query, "\\s+")[[1]])
  
  expanded_terms <- original_terms
  
  # Process each term in the query
  for (term in original_terms) {
    
    # Find matching concepts
    concept_matches <- find_vocabulary_matches(term)
    
    if (length(concept_matches) > 0) {
      
      for (concept_id in concept_matches) {
        concept <- get_concept_by_id(concept_id)
        
        if (!is.null(concept)) {
          
          # Add narrower terms (more specific)
          if (!is.null(concept$narrower)) {
            narrower_labels <- get_concept_labels(concept$narrower)
            expanded_terms <- c(expanded_terms, narrower_labels)
          }
          
          # Add related terms
          if (!is.null(concept$related)) {
            related_labels <- get_concept_labels(concept$related)
            expanded_terms <- c(expanded_terms, related_labels)
          }
          
          # Add synonyms if requested
          if (include_synonyms && !is.null(concept$synonyms)) {
            expanded_terms <- c(expanded_terms, concept$synonyms)
          }
        }
      }
    }
  }
  
  # Remove duplicates and limit terms
  unique_terms <- unique(expanded_terms)
  final_terms <- head(unique_terms, max_terms)
  
  # Create expanded query
  expanded_query <- paste(final_terms, collapse = " OR ")
  
  log_event(paste("Vocabulary expansion:", length(original_terms), "->", length(final_terms), "terms"))
  
  return(expanded_query)
}

#' Find vocabulary matches for a search term
#' @param term Search term
#' @return Vector of matching concept IDs
find_vocabulary_matches <- function(term) {
  
  if (is.null(term) || nchar(trimws(term)) == 0) {
    return(character(0))
  }
  
  term_lower <- str_to_lower(str_trim(term))
  matches <- character(0)
  
  # Search in all vocabulary levels
  all_concepts <- c(
    TRANSPORT_VOCABULARY$primary,
    TRANSPORT_VOCABULARY$secondary, 
    TRANSPORT_VOCABULARY$tertiary
  )
  
  for (concept_id in names(all_concepts)) {
    concept <- all_concepts[[concept_id]]
    
    # Check prefLabel
    if (!is.null(concept$prefLabel)) {
      if (str_detect(str_to_lower(concept$prefLabel), term_lower)) {
        matches <- c(matches, concept_id)
        next
      }
    }
    
    # Check synonyms
    if (!is.null(concept$synonyms)) {
      for (synonym in concept$synonyms) {
        if (str_detect(str_to_lower(synonym), term_lower)) {
          matches <- c(matches, concept_id)
          break
        }
      }
    }
    
    # Check if term matches concept ID
    if (str_detect(concept_id, term_lower)) {
      matches <- c(matches, concept_id)
    }
  }
  
  return(unique(matches))
}

#' Get concept by ID from vocabulary
#' @param concept_id Concept identifier
#' @return Concept object or NULL
get_concept_by_id <- function(concept_id) {
  
  # Search in primary concepts
  if (concept_id %in% names(TRANSPORT_VOCABULARY$primary)) {
    return(TRANSPORT_VOCABULARY$primary[[concept_id]])
  }
  
  # Search in secondary concepts
  if (concept_id %in% names(TRANSPORT_VOCABULARY$secondary)) {
    return(TRANSPORT_VOCABULARY$secondary[[concept_id]])
  }
  
  # Search in tertiary concepts
  if (concept_id %in% names(TRANSPORT_VOCABULARY$tertiary)) {
    return(TRANSPORT_VOCABULARY$tertiary[[concept_id]])
  }
  
  return(NULL)
}

#' Get labels for concept IDs
#' @param concept_ids Vector of concept IDs
#' @return Vector of human-readable labels
get_concept_labels <- function(concept_ids) {
  
  if (is.null(concept_ids) || length(concept_ids) == 0) {
    return(character(0))
  }
  
  labels <- sapply(concept_ids, function(id) {
    concept <- get_concept_by_id(id)
    if (!is.null(concept) && !is.null(concept$prefLabel)) {
      return(concept$prefLabel)
    } else {
      # Return formatted ID as fallback
      return(str_replace_all(id, "_", " "))
    }
  })
  
  return(as.character(labels))
}

#' Generate vocabulary suggestions for search interface
#' @param partial_query Partial query string
#' @param max_suggestions Maximum number of suggestions
#' @return List of vocabulary suggestions
suggest_vocabulary_terms <- function(partial_query = "", max_suggestions = 10) {
  
  if (is.null(partial_query)) partial_query <- ""
  
  # Get all concept labels
  all_labels <- get_all_concept_labels()
  
  if (nchar(trimws(partial_query)) == 0) {
    # Return popular transport terms
    popular_terms <- c(
      "Transporte público", "Mobilidade urbana", "Ônibus", "Metrô", 
      "Ciclovia", "BRT", "Semáforo", "Estacionamento", "Trânsito", "Via pública"
    )
    return(head(popular_terms, max_suggestions))
  }
  
  # Filter labels based on partial query
  query_lower <- str_to_lower(partial_query)
  
  matching_labels <- all_labels[str_detect(str_to_lower(all_labels), query_lower)]
  
  # Sort by relevance (exact matches first, then contains)
  exact_matches <- matching_labels[str_to_lower(matching_labels) == query_lower]
  starts_with <- matching_labels[str_starts(str_to_lower(matching_labels), query_lower)]
  contains <- matching_labels[str_detect(str_to_lower(matching_labels), query_lower)]
  
  # Combine and remove duplicates
  suggestions <- unique(c(exact_matches, starts_with, contains))
  
  return(head(suggestions, max_suggestions))
}

#' Get all concept labels from vocabulary
#' @return Vector of all labels
get_all_concept_labels <- function() {
  
  labels <- character(0)
  
  # Collect from all vocabulary levels
  all_concepts <- c(
    TRANSPORT_VOCABULARY$primary,
    TRANSPORT_VOCABULARY$secondary,
    TRANSPORT_VOCABULARY$tertiary
  )
  
  for (concept in all_concepts) {
    # Add prefLabel
    if (!is.null(concept$prefLabel)) {
      labels <- c(labels, concept$prefLabel)
    }
    
    # Add synonyms
    if (!is.null(concept$synonyms)) {
      labels <- c(labels, concept$synonyms)
    }
  }
  
  return(unique(labels))
}

#' Create vocabulary hierarchy for navigation
#' @param root_concept Root concept ID (NULL for all)
#' @return Hierarchical list structure
create_vocabulary_hierarchy <- function(root_concept = NULL) {
  
  if (is.null(root_concept)) {
    # Return top-level concepts
    hierarchy <- list()
    
    for (concept_id in names(TRANSPORT_VOCABULARY$primary)) {
      concept <- TRANSPORT_VOCABULARY$primary[[concept_id]]
      hierarchy[[concept_id]] <- list(
        label = concept$prefLabel,
        definition = concept$definition,
        children = create_concept_children(concept_id)
      )
    }
    
    return(hierarchy)
  } else {
    # Return hierarchy for specific concept
    return(create_concept_children(root_concept))
  }
}

#' Create children hierarchy for a concept
#' @param concept_id Parent concept ID
#' @return List of child concepts
create_concept_children <- function(concept_id) {
  
  concept <- get_concept_by_id(concept_id)
  if (is.null(concept) || is.null(concept$narrower)) {
    return(list())
  }
  
  children <- list()
  
  for (child_id in concept$narrower) {
    child_concept <- get_concept_by_id(child_id)
    if (!is.null(child_concept)) {
      children[[child_id]] <- list(
        label = child_concept$prefLabel,
        definition = child_concept$definition,
        children = create_concept_children(child_id)
      )
    }
  }
  
  return(children)
}

#' Analyze query coverage against vocabulary
#' @param query Search query
#' @return Analysis results
analyze_vocabulary_coverage <- function(query) {
  
  if (is.null(query) || nchar(trimws(query)) == 0) {
    return(list(
      coverage_percentage = 0,
      matched_terms = character(0),
      suggested_terms = character(0),
      analysis = "Query vazia"
    ))
  }
  
  # Extract terms from query
  query_terms <- unique(str_split(str_to_lower(query), "\\s+")[[1]])
  query_terms <- query_terms[nchar(query_terms) > 2]  # Filter short terms
  
  # Check matches
  matched_terms <- character(0)
  
  for (term in query_terms) {
    matches <- find_vocabulary_matches(term)
    if (length(matches) > 0) {
      matched_terms <- c(matched_terms, term)
    }
  }
  
  # Calculate coverage
  coverage_percentage <- if (length(query_terms) > 0) {
    round((length(matched_terms) / length(query_terms)) * 100, 1)
  } else {
    0
  }
  
  # Generate suggestions for unmatched terms
  unmatched_terms <- setdiff(query_terms, matched_terms)
  suggested_terms <- character(0)
  
  for (unmatched in unmatched_terms) {
    suggestions <- suggest_vocabulary_terms(unmatched, 3)
    suggested_terms <- c(suggested_terms, suggestions)
  }
  
  # Analysis summary
  analysis <- if (coverage_percentage >= 80) {
    "Excelente cobertura vocabular"
  } else if (coverage_percentage >= 60) {
    "Boa cobertura vocabular"
  } else if (coverage_percentage >= 40) {
    "Cobertura vocabular moderada"
  } else {
    "Baixa cobertura vocabular - considere termos mais específicos"
  }
  
  return(list(
    coverage_percentage = coverage_percentage,
    matched_terms = matched_terms,
    unmatched_terms = unmatched_terms,
    suggested_terms = unique(suggested_terms),
    analysis = analysis,
    total_terms = length(query_terms)
  ))
}

#' Export vocabulary to SKOS RDF format
#' @param file_path Output file path
#' @return Success boolean
export_vocabulary_to_skos <- function(file_path) {
  
  tryCatch({
    
    # Create SKOS namespace and structure
    skos_content <- create_skos_document()
    
    # Write to file
    writeLines(skos_content, file_path, useBytes = TRUE)
    
    log_event(paste("Vocabulary exported to SKOS:", file_path))
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Error exporting SKOS:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Create SKOS RDF document
#' @return SKOS XML content as character vector
create_skos_document <- function() {
  
  # SKOS document header
  header <- c(
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rdf:RDF',
    '  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"',
    '  xmlns:skos="http://www.w3.org/2004/02/skos/core#"',
    '  xmlns:dc="http://purl.org/dc/elements/1.1/"',
    '  xmlns:foaf="http://xmlns.com/foaf/0.1/">',
    '',
    '  <!-- Transport Legislation Vocabulary for Monitor Legislativo v4 -->',
    '  <skos:ConceptScheme rdf:about="http://monitorlegislativo.gov.br/vocab/transport">',
    '    <dc:title>Vocabulário de Legislação de Transportes</dc:title>',
    '    <dc:description>Vocabulário controlado para legislação brasileira de transportes e mobilidade urbana</dc:description>',
    '    <dc:creator>Monitor Legislativo v4</dc:creator>',
    '    <dc:date>2025-01-07</dc:date>',
    '  </skos:ConceptScheme>',
    ''
  )
  
  # Process all concepts
  concepts_xml <- character(0)
  
  all_concepts <- c(
    TRANSPORT_VOCABULARY$primary,
    TRANSPORT_VOCABULARY$secondary,
    TRANSPORT_VOCABULARY$tertiary
  )
  
  for (concept_id in names(all_concepts)) {
    concept_xml <- create_skos_concept(concept_id, all_concepts[[concept_id]])
    concepts_xml <- c(concepts_xml, concept_xml, "")
  }
  
  # Document footer
  footer <- "</rdf:RDF>"
  
  return(c(header, concepts_xml, footer))
}

#' Create SKOS concept XML
#' @param concept_id Concept identifier
#' @param concept Concept data
#' @return XML lines for concept
create_skos_concept <- function(concept_id, concept) {
  
  concept_uri <- paste0("http://monitorlegislativo.gov.br/vocab/transport#", concept_id)
  
  xml_lines <- c(
    paste0('  <skos:Concept rdf:about="', concept_uri, '">'),
    paste0('    <skos:prefLabel xml:lang="pt">', concept$prefLabel, '</skos:prefLabel>')
  )
  
  # Add definition
  if (!is.null(concept$definition)) {
    xml_lines <- c(xml_lines, 
      paste0('    <skos:definition xml:lang="pt">', concept$definition, '</skos:definition>'))
  }
  
  # Add broader relationship
  if (!is.null(concept$broader)) {
    broader_uri <- paste0("http://monitorlegislativo.gov.br/vocab/transport#", concept$broader)
    xml_lines <- c(xml_lines,
      paste0('    <skos:broader rdf:resource="', broader_uri, '"/>'))
  }
  
  # Add narrower relationships
  if (!is.null(concept$narrower)) {
    for (narrower_id in concept$narrower) {
      narrower_uri <- paste0("http://monitorlegislativo.gov.br/vocab/transport#", narrower_id)
      xml_lines <- c(xml_lines,
        paste0('    <skos:narrower rdf:resource="', narrower_uri, '"/>'))
    }
  }
  
  # Add related relationships
  if (!is.null(concept$related)) {
    for (related_id in concept$related) {
      related_uri <- paste0("http://monitorlegislativo.gov.br/vocab/transport#", related_id)
      xml_lines <- c(xml_lines,
        paste0('    <skos:related rdf:resource="', related_uri, '"/>'))
    }
  }
  
  # Add synonyms as altLabel
  if (!is.null(concept$synonyms)) {
    for (synonym in concept$synonyms) {
      xml_lines <- c(xml_lines,
        paste0('    <skos:altLabel xml:lang="pt">', synonym, '</skos:altLabel>'))
    }
  }
  
  # Add concept scheme
  xml_lines <- c(xml_lines,
    '    <skos:inScheme rdf:resource="http://monitorlegislativo.gov.br/vocab/transport"/>',
    '  </skos:Concept>'
  )
  
  return(xml_lines)
}

#' Load vocabulary from external SKOS file
#' @param file_path Path to SKOS file
#' @return Success boolean
load_vocabulary_from_skos <- function(file_path) {
  
  tryCatch({
    
    if (!file.exists(file_path)) {
      log_event(paste("SKOS file not found:", file_path), "WARN")
      return(FALSE)
    }
    
    # Parse SKOS XML
    skos_doc <- xml2::read_xml(file_path)
    
    # Extract concepts (simplified implementation)
    concepts <- xml2::xml_find_all(skos_doc, "//skos:Concept")
    
    log_event(paste("Loaded", length(concepts), "concepts from SKOS file"))
    
    # Here you would implement full SKOS parsing
    # For now, return success
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Error loading SKOS file:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Get vocabulary statistics
#' @return List with vocabulary metrics
get_vocabulary_statistics <- function() {
  
  primary_count <- length(TRANSPORT_VOCABULARY$primary)
  secondary_count <- length(TRANSPORT_VOCABULARY$secondary)
  tertiary_count <- length(TRANSPORT_VOCABULARY$tertiary)
  
  total_concepts <- primary_count + secondary_count + tertiary_count
  
  # Count relationships
  total_relationships <- 0
  all_concepts <- c(
    TRANSPORT_VOCABULARY$primary,
    TRANSPORT_VOCABULARY$secondary,
    TRANSPORT_VOCABULARY$tertiary
  )
  
  for (concept in all_concepts) {
    if (!is.null(concept$narrower)) total_relationships <- total_relationships + length(concept$narrower)
    if (!is.null(concept$related)) total_relationships <- total_relationships + length(concept$related)
  }
  
  # Count synonyms
  total_synonyms <- 0
  for (concept in all_concepts) {
    if (!is.null(concept$synonyms)) total_synonyms <- total_synonyms + length(concept$synonyms)
  }
  
  return(list(
    total_concepts = total_concepts,
    primary_concepts = primary_count,
    secondary_concepts = secondary_count,
    tertiary_concepts = tertiary_count,
    total_relationships = total_relationships,
    total_synonyms = total_synonyms,
    coverage_domains = c("Transporte", "Mobilidade", "Infraestrutura"),
    last_updated = Sys.Date()
  ))
}