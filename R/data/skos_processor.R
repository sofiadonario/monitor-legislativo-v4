# SKOS Vocabulary Processor - Phase 2 Week 3 Implementation
# Monitor Legislativo v4 - Semantic Knowledge Organization System
# ==============================================================

#' SKOS Vocabulary Processor for Brazilian Legal Terminology
#' 
#' Comprehensive processor for Simple Knowledge Organization System (SKOS)
#' vocabularies specifically designed for Brazilian legal terminology.
#' This module processes hierarchical legal vocabularies, manages concept
#' relationships, and provides semantic search capabilities for legislative
#' document classification and analysis.
#' 
#' SKOS is a W3C standard for representing knowledge organization systems
#' such as thesauri, classification schemes, subject heading lists, and
#' taxonomies. This implementation focuses on Brazilian legal terminology
#' following the LexML vocabulary standards and integrates with the
#' Vocabulário Controlado Básico (VCB) used in Brazilian legal informatics.
#' 
#' @details
#' **Core SKOS Concepts Supported:**
#' - **skos:Concept** - Individual legal concepts and terms
#' - **skos:ConceptScheme** - Legal classification schemes
#' - **skos:prefLabel** - Preferred Portuguese legal terms
#' - **skos:altLabel** - Alternative terms and synonyms
#' - **skos:broader/narrower** - Hierarchical concept relationships
#' - **skos:related** - Associative concept relationships
#' - **skos:definition** - Legal concept definitions in Portuguese
#' 
#' **Brazilian Legal Vocabularies:**
#' - Document types (tipos de documentos jurídicos)
#' - Geographic jurisdictions (jurisdições territoriais)
#' - Legal subjects (assuntos jurídicos)
#' - Administrative levels (níveis administrativos)
#' - Legal processes (processos jurídicos)
#' 
#' **Academic Features:**
#' - Semantic similarity calculations for legal concepts
#' - Automated document classification using legal taxonomies
#' - Legal term expansion for comprehensive search
#' - Research-grade vocabulary validation and quality metrics
#' 
#' @author Monitor Legislativo v4 Team
#' @family semantic-processing
#' @import jsonlite
#' @import xml2
#' @import dplyr
#' @import stringr
#' @export

library(jsonlite)
library(xml2)
library(dplyr)
library(stringr)
library(digest)

# SKOS vocabulary URIs and namespaces
SKOS_NAMESPACE <- "http://www.w3.org/2004/02/skos/core#"
LEXML_VOCAB_BASE <- "https://www.lexml.gov.br/vocabulario/"
VCB_BASE_URI <- "https://www.lexml.gov.br/vcb/"

# Legal terminology categories
LEGAL_CATEGORIES <- c(
  "tipos_documento" = "Document Types",
  "jurisdicoes" = "Jurisdictions", 
  "assuntos" = "Legal Subjects",
  "niveis_administrativos" = "Administrative Levels",
  "processos" = "Legal Processes",
  "orgaos" = "Government Bodies",
  "materias" = "Legal Matters"
)

#' Initialize SKOS Vocabulary Processor
#' 
#' Sets up the SKOS processor with Brazilian legal vocabulary configurations,
#' namespace definitions, and processing parameters optimized for legal
#' terminology analysis and semantic search operations.
#' 
#' @param cache_dir Directory for caching processed vocabularies
#' @param language Primary language code (default: "pt-BR")
#' @param enable_fuzzy Enable fuzzy matching for concept recognition
#' @return Initialized SKOS processor configuration
#' @export
initialize_skos_processor <- function(cache_dir = "cache/skos", 
                                     language = "pt-BR",
                                     enable_fuzzy = TRUE) {
  tryCatch({
    # Create cache directory if it doesn't exist
    if (!dir.exists(cache_dir)) {
      dir.create(cache_dir, recursive = TRUE)
    }
    
    processor_config <- list(
      cache_dir = cache_dir,
      language = language,
      enable_fuzzy = enable_fuzzy,
      namespaces = list(
        skos = SKOS_NAMESPACE,
        lexml = LEXML_VOCAB_BASE,
        vcb = VCB_BASE_URI
      ),
      categories = LEGAL_CATEGORIES,
      initialized_at = Sys.time()
    )
    
    cat("✅ SKOS Vocabulary Processor initialized\n")
    cat("   Cache directory:", cache_dir, "\n")
    cat("   Language:", language, "\n")
    cat("   Fuzzy matching:", ifelse(enable_fuzzy, "enabled", "disabled"), "\n")
    cat("   Legal categories:", length(LEGAL_CATEGORIES), "\n")
    
    return(processor_config)
    
  }, error = function(e) {
    cat("❌ Error initializing SKOS processor:", e$message, "\n")
    return(NULL)
  })
}

#' Process SKOS Legal Vocabulary
#' 
#' Processes raw SKOS/RDF vocabulary data from Brazilian legal sources,
#' extracting concept hierarchies, relationships, and metadata for use
#' in semantic search and document classification systems.
#' 
#' @param vocab_data Raw vocabulary data (JSON, XML, or RDF)
#' @param vocab_type Type of vocabulary ("tipos", "jurisdicoes", "assuntos")
#' @param source_format Format of input data ("json", "xml", "rdf")
#' @return Processed vocabulary structure with concepts and relationships
#' @export
process_skos_vocabulary <- function(vocab_data, vocab_type, source_format = "json") {
  
  start_time <- Sys.time()
  
  tryCatch({
    # Validate input parameters
    if (!vocab_type %in% names(LEGAL_CATEGORIES)) {
      stop("Unsupported vocabulary type: ", vocab_type)
    }
    
    # Parse vocabulary data based on format
    parsed_vocab <- switch(source_format,
      "json" = parse_json_vocabulary(vocab_data),
      "xml" = parse_xml_vocabulary(vocab_data),
      "rdf" = parse_rdf_vocabulary(vocab_data),
      stop("Unsupported format: ", source_format)
    )
    
    # Extract SKOS concepts
    concepts <- extract_skos_concepts(parsed_vocab, vocab_type)
    
    # Build concept hierarchy
    hierarchy <- build_concept_hierarchy(concepts)
    
    # Extract relationships
    relationships <- extract_concept_relationships(concepts)
    
    # Generate search indices
    search_indices <- build_search_indices(concepts)
    
    # Calculate performance metrics
    end_time <- Sys.time()
    processing_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    
    # Build processed vocabulary structure
    processed_vocab <- list(
      metadata = list(
        type = vocab_type,
        category = LEGAL_CATEGORIES[[vocab_type]],
        source_format = source_format,
        total_concepts = length(concepts),
        processing_time = processing_time,
        processed_at = Sys.time(),
        language = "pt-BR"
      ),
      concepts = concepts,
      hierarchy = hierarchy,
      relationships = relationships,
      search_indices = search_indices,
      statistics = calculate_vocabulary_statistics(concepts, relationships)
    )
    
    cat("✅ SKOS vocabulary processed successfully\n")
    cat("   Type:", vocab_type, "(", LEGAL_CATEGORIES[[vocab_type]], ")\n")
    cat("   Concepts:", length(concepts), "\n")
    cat("   Hierarchical levels:", max(sapply(hierarchy, function(x) x$level), na.rm = TRUE), "\n")
    cat("   Processing time:", round(processing_time, 2), "seconds\n")
    
    return(processed_vocab)
    
  }, error = function(e) {
    cat("❌ Error processing SKOS vocabulary:", e$message, "\n")
    return(list(concepts = list(), error = e$message))
  })
}

#' Extract SKOS Concepts from Raw Data
#' 
#' Extracts individual concepts with their properties, labels, and definitions
#' from parsed vocabulary data, normalizing them for Brazilian legal terminology.
#' 
#' @param parsed_data Parsed vocabulary data
#' @param vocab_type Vocabulary type for context
#' @return List of extracted concepts with normalized properties
extract_skos_concepts <- function(parsed_data, vocab_type) {
  
  tryCatch({
    concepts <- list()
    
    # Handle different data structures
    concept_list <- if (is.list(parsed_data$concepts)) {
      parsed_data$concepts
    } else if (is.list(parsed_data)) {
      parsed_data
    } else {
      stop("Invalid vocabulary data structure")
    }
    
    for (i in seq_along(concept_list)) {
      concept_raw <- concept_list[[i]]
      
      # Extract concept properties
      concept <- list(
        # Core identification
        uri = concept_raw$uri %||% concept_raw$id %||% paste0(VCB_BASE_URI, vocab_type, "/", i),
        prefLabel = normalize_legal_term(concept_raw$prefLabel %||% concept_raw$label %||% concept_raw$nome),
        
        # Alternative labels
        altLabels = normalize_alt_labels(concept_raw$altLabel %||% concept_raw$synonyms %||% list()),
        
        # Relationships
        broader = concept_raw$broader %||% concept_raw$parent %||% character(),
        narrower = concept_raw$narrower %||% concept_raw$children %||% list(),
        related = concept_raw$related %||% concept_raw$associated %||% list(),
        
        # Content
        definition = concept_raw$definition %||% concept_raw$description %||% NA_character_,
        scope_note = concept_raw$scopeNote %||% concept_raw$note %||% NA_character_,
        example = concept_raw$example %||% concept_raw$exemplo %||% NA_character_,
        
        # Classification
        category = vocab_type,
        scheme = concept_raw$scheme %||% paste0("lexml:", vocab_type),
        
        # Metadata
        created = parse_date_safe(concept_raw$created),
        modified = parse_date_safe(concept_raw$modified),
        
        # Usage and frequency (for search optimization)
        usage_frequency = concept_raw$frequency %||% 1,
        search_weight = calculate_concept_weight(concept_raw, vocab_type)
      )
      
      # Generate unique concept ID
      concept_id <- generate_concept_id(concept$prefLabel, concept$uri)
      concepts[[concept_id]] <- concept
    }
    
    cat("✅ Extracted", length(concepts), "SKOS concepts\n")
    return(concepts)
    
  }, error = function(e) {
    cat("❌ Error extracting SKOS concepts:", e$message, "\n")
    return(list())
  })
}

#' Build Concept Hierarchy
#' 
#' Constructs hierarchical relationships between legal concepts,
#' calculating depth levels and parent-child relationships for
#' browsing and semantic search operations.
#' 
#' @param concepts List of processed concepts
#' @return Hierarchical structure with levels and relationships
build_concept_hierarchy <- function(concepts) {
  
  tryCatch({
    hierarchy <- list()
    
    for (concept_id in names(concepts)) {
      concept <- concepts[[concept_id]]
      
      # Determine hierarchical level
      level <- calculate_concept_level(concept, concepts)
      
      # Find parent concepts
      parents <- find_parent_concepts(concept, concepts)
      
      # Find child concepts
      children <- find_child_concepts(concept, concepts)
      
      hierarchy[[concept_id]] <- list(
        concept_id = concept_id,
        prefLabel = concept$prefLabel,
        level = level,
        parents = parents,
        children = children,
        has_children = length(children) > 0,
        is_root = length(parents) == 0,
        path = build_concept_path(concept, concepts)
      )
    }
    
    cat("✅ Built concept hierarchy with", length(hierarchy), "nodes\n")
    return(hierarchy)
    
  }, error = function(e) {
    cat("❌ Error building concept hierarchy:", e$message, "\n")
    return(list())
  })
}

#' Extract Concept Relationships
#' 
#' Extracts and normalizes all types of relationships between legal concepts
#' including hierarchical (broader/narrower) and associative (related) relationships.
#' 
#' @param concepts List of processed concepts
#' @return Structured relationship data for semantic navigation
extract_concept_relationships <- function(concepts) {
  
  relationships <- list(
    broader = list(),      # Parent relationships
    narrower = list(),     # Child relationships  
    related = list(),      # Associative relationships
    equivalent = list()    # Equivalent concepts
  )
  
  tryCatch({
    for (concept_id in names(concepts)) {
      concept <- concepts[[concept_id]]
      
      # Extract broader relationships
      if (length(concept$broader) > 0) {
        for (broader_uri in concept$broader) {
          broader_id <- find_concept_by_uri(broader_uri, concepts)
          if (!is.null(broader_id)) {
            relationships$broader[[concept_id]] <- c(relationships$broader[[concept_id]], broader_id)
          }
        }
      }
      
      # Extract narrower relationships
      if (length(concept$narrower) > 0) {
        for (narrower_uri in concept$narrower) {
          narrower_id <- find_concept_by_uri(narrower_uri, concepts)
          if (!is.null(narrower_id)) {
            relationships$narrower[[concept_id]] <- c(relationships$narrower[[concept_id]], narrower_id)
          }
        }
      }
      
      # Extract related relationships
      if (length(concept$related) > 0) {
        for (related_uri in concept$related) {
          related_id <- find_concept_by_uri(related_uri, concepts)
          if (!is.null(related_id)) {
            relationships$related[[concept_id]] <- c(relationships$related[[concept_id]], related_id)
          }
        }
      }
    }
    
    # Calculate relationship statistics
    rel_stats <- list(
      total_broader = length(unlist(relationships$broader)),
      total_narrower = length(unlist(relationships$narrower)),
      total_related = length(unlist(relationships$related)),
      concepts_with_parents = length(relationships$broader),
      concepts_with_children = length(relationships$narrower)
    )
    
    cat("✅ Extracted concept relationships\n")
    cat("   Broader (parent):", rel_stats$total_broader, "\n")
    cat("   Narrower (child):", rel_stats$total_narrower, "\n")
    cat("   Related (associative):", rel_stats$total_related, "\n")
    
    return(list(
      relationships = relationships,
      statistics = rel_stats
    ))
    
  }, error = function(e) {
    cat("❌ Error extracting relationships:", e$message, "\n")
    return(list(relationships = list(), statistics = list()))
  })
}

#' Build Search Indices for Legal Concepts
#' 
#' Creates optimized search indices for fast lookup of legal concepts
#' by preferred labels, alternative labels, and partial matches.
#' 
#' @param concepts List of processed concepts
#' @return Search indices for efficient concept lookup
build_search_indices <- function(concepts) {
  
  tryCatch({
    indices <- list(
      by_label = list(),         # Exact label matches
      by_partial = list(),       # Partial matches
      by_category = list(),      # Category-based grouping
      by_frequency = list()      # Frequency-based ranking
    )
    
    for (concept_id in names(concepts)) {
      concept <- concepts[[concept_id]]
      
      # Index by preferred label
      clean_label <- tolower(str_trim(concept$prefLabel))
      indices$by_label[[clean_label]] <- concept_id
      
      # Index by alternative labels
      if (length(concept$altLabels) > 0) {
        for (alt_label in concept$altLabels) {
          clean_alt <- tolower(str_trim(alt_label))
          indices$by_label[[clean_alt]] <- concept_id
        }
      }
      
      # Index by partial matches (for autocomplete)
      words <- str_split(clean_label, "\\s+")[[1]]
      for (word in words) {
        if (nchar(word) >= 3) {  # Index words with 3+ characters
          if (is.null(indices$by_partial[[word]])) {
            indices$by_partial[[word]] <- character()
          }
          indices$by_partial[[word]] <- c(indices$by_partial[[word]], concept_id)
        }
      }
      
      # Index by category
      category <- concept$category
      if (is.null(indices$by_category[[category]])) {
        indices$by_category[[category]] <- character()
      }
      indices$by_category[[category]] <- c(indices$by_category[[category]], concept_id)
      
      # Index by frequency for ranking
      freq_bucket <- categorize_frequency(concept$usage_frequency)
      if (is.null(indices$by_frequency[[freq_bucket]])) {
        indices$by_frequency[[freq_bucket]] <- character()
      }
      indices$by_frequency[[freq_bucket]] <- c(indices$by_frequency[[freq_bucket]], concept_id)
    }
    
    # Create reverse indices for relationships
    indices$reverse_lookup <- create_reverse_lookup(concepts)
    
    cat("✅ Built search indices\n")
    cat("   Exact labels:", length(indices$by_label), "\n")
    cat("   Partial terms:", length(indices$by_partial), "\n")
    cat("   Categories:", length(indices$by_category), "\n")
    
    return(indices)
    
  }, error = function(e) {
    cat("❌ Error building search indices:", e$message, "\n")
    return(list())
  })
}

#' Search Legal Concepts
#' 
#' Performs intelligent search across legal concepts using exact matches,
#' partial matches, and semantic relationships to find relevant legal terms.
#' 
#' @param query Search query string
#' @param processed_vocab Processed vocabulary with search indices
#' @param max_results Maximum number of results to return
#' @param include_alternatives Include alternative labels in search
#' @param semantic_expansion Expand search using related concepts
#' @return Ranked list of matching concepts
#' @export
search_legal_concepts <- function(query, processed_vocab, max_results = 20, 
                                include_alternatives = TRUE, semantic_expansion = FALSE) {
  
  tryCatch({
    if (length(processed_vocab$concepts) == 0) {
      return(list())
    }
    
    query_clean <- tolower(str_trim(query))
    results <- list()
    
    # 1. Exact label matches (highest priority)
    exact_match <- processed_vocab$search_indices$by_label[[query_clean]]
    if (!is.null(exact_match)) {
      concept <- processed_vocab$concepts[[exact_match]]
      results[[exact_match]] <- list(
        concept_id = exact_match,
        concept = concept,
        match_type = "exact",
        relevance_score = 1.0
      )
    }
    
    # 2. Partial matches
    query_words <- str_split(query_clean, "\\s+")[[1]]
    partial_matches <- character()
    
    for (word in query_words) {
      if (nchar(word) >= 3) {
        matches <- processed_vocab$search_indices$by_partial[[word]]
        if (!is.null(matches)) {
          partial_matches <- c(partial_matches, matches)
        }
      }
    }
    
    # Score partial matches
    for (concept_id in unique(partial_matches)) {
      if (!concept_id %in% names(results)) {
        concept <- processed_vocab$concepts[[concept_id]]
        score <- calculate_relevance_score(query_clean, concept, "partial")
        
        results[[concept_id]] <- list(
          concept_id = concept_id,
          concept = concept,
          match_type = "partial",
          relevance_score = score
        )
      }
    }
    
    # 3. Fuzzy matches (if enabled)
    if (length(results) < max_results) {
      fuzzy_matches <- find_fuzzy_matches(query_clean, processed_vocab$concepts)
      for (match in fuzzy_matches) {
        if (!match$concept_id %in% names(results)) {
          results[[match$concept_id]] <- match
        }
      }
    }
    
    # 4. Semantic expansion (if requested)
    if (semantic_expansion && length(results) > 0) {
      expanded_results <- perform_semantic_expansion(results, processed_vocab)
      results <- c(results, expanded_results)
    }
    
    # Sort by relevance score and limit results
    sorted_results <- results[order(sapply(results, function(x) x$relevance_score), decreasing = TRUE)]
    final_results <- head(sorted_results, max_results)
    
    cat("✅ Found", length(final_results), "concept matches for query:", query, "\n")
    
    return(final_results)
    
  }, error = function(e) {
    cat("❌ Error searching legal concepts:", e$message, "\n")
    return(list())
  })
}

# Helper Functions
# ================

#' Parse different vocabulary formats
parse_json_vocabulary <- function(data) {
  if (is.character(data)) {
    return(fromJSON(data, simplifyVector = FALSE))
  } else {
    return(data)
  }
}

parse_xml_vocabulary <- function(data) {
  # Placeholder for XML parsing
  # In a full implementation, this would parse SKOS/RDF XML
  stop("XML parsing not yet implemented")
}

parse_rdf_vocabulary <- function(data) {
  # Placeholder for RDF parsing
  # In a full implementation, this would use rdflib or similar
  stop("RDF parsing not yet implemented")
}

#' Normalize legal terms to standard format
normalize_legal_term <- function(term) {
  if (is.null(term) || is.na(term)) return(NA_character_)
  
  # Clean and normalize
  term <- str_trim(term)
  term <- str_replace_all(term, "\\s+", " ")  # Multiple spaces to single
  term <- str_to_title(term)  # Title case for legal terms
  
  return(term)
}

#' Normalize alternative labels
normalize_alt_labels <- function(labels) {
  if (is.null(labels) || length(labels) == 0) return(character())
  
  if (is.character(labels)) {
    return(sapply(labels, normalize_legal_term, USE.NAMES = FALSE))
  } else if (is.list(labels)) {
    return(sapply(unlist(labels), normalize_legal_term, USE.NAMES = FALSE))
  }
  
  return(character())
}

#' Calculate concept weight for search ranking
calculate_concept_weight <- function(concept_raw, vocab_type) {
  base_weight <- 1.0
  
  # Boost weight based on vocabulary type importance
  type_weights <- c(
    "tipos_documento" = 1.5,
    "jurisdicoes" = 1.3,
    "assuntos" = 1.2,
    "materias" = 1.1
  )
  
  type_boost <- type_weights[[vocab_type]] %||% 1.0
  
  # Boost for frequently used terms
  freq_boost <- if (!is.null(concept_raw$frequency)) {
    min(concept_raw$frequency / 100, 2.0)  # Cap at 2x boost
  } else {
    1.0
  }
  
  return(base_weight * type_boost * freq_boost)
}

#' Generate unique concept ID
generate_concept_id <- function(label, uri) {
  if (!is.na(label) && nchar(label) > 0) {
    # Use normalized label as base
    base <- str_replace_all(tolower(label), "[^a-z0-9]", "_")
    base <- str_replace_all(base, "_+", "_")
    base <- str_remove_all(base, "^_|_$")
  } else {
    # Fallback to URI hash
    base <- substr(digest(uri, algo = "md5"), 1, 8)
  }
  
  return(base)
}

#' Safe date parsing
parse_date_safe <- function(date_string) {
  if (is.null(date_string) || is.na(date_string)) return(NA)
  
  tryCatch({
    as.Date(date_string)
  }, error = function(e) {
    NA
  })
}

#' Calculate vocabulary statistics
calculate_vocabulary_statistics <- function(concepts, relationships) {
  list(
    total_concepts = length(concepts),
    concepts_with_definitions = sum(!is.na(sapply(concepts, function(x) x$definition))),
    concepts_with_alternatives = sum(sapply(concepts, function(x) length(x$altLabels) > 0)),
    average_hierarchy_depth = calculate_average_depth(concepts),
    relationship_density = calculate_relationship_density(relationships$relationships)
  )
}

#' Calculate average hierarchy depth
calculate_average_depth <- function(concepts) {
  depths <- sapply(concepts, function(concept) {
    # Simple depth calculation based on broader relationships
    depth <- 0
    current_broader <- concept$broader
    visited <- character()
    
    while (length(current_broader) > 0 && !current_broader[1] %in% visited) {
      depth <- depth + 1
      visited <- c(visited, current_broader[1])
      # Find parent concept
      parent_concept <- find_concept_by_uri(current_broader[1], concepts)
      if (!is.null(parent_concept)) {
        current_broader <- concepts[[parent_concept]]$broader
      } else {
        break
      }
    }
    
    return(depth)
  })
  
  return(mean(depths, na.rm = TRUE))
}

#' Calculate relationship density
calculate_relationship_density <- function(relationships) {
  total_relations <- length(unlist(relationships$broader)) + 
                    length(unlist(relationships$narrower)) + 
                    length(unlist(relationships$related))
  
  total_concepts <- length(unique(c(names(relationships$broader),
                                   names(relationships$narrower),
                                   names(relationships$related))))
  
  if (total_concepts == 0) return(0)
  
  return(total_relations / total_concepts)
}

# Null coalescing operator
`%||%` <- function(x, y) if (is.null(x) || length(x) == 0 || is.na(x)) y else x

cat("✅ SKOS Vocabulary Processor loaded - Phase 2 Week 3 Implementation\n")
cat("   Semantic processing for Brazilian legal terminology\n")
cat("   Features: Concept extraction, hierarchy building, search indices\n")
cat("   SKOS compliance with legal vocabulary standards\n")