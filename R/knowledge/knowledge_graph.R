# ============================================================================
# KNOWLEDGE GRAPH IMPLEMENTATION - WEEK 10 PHASE 3
# ============================================================================
# 
# Advanced knowledge graph for Brazilian legislative relationships
# Monitor Legislativo v4 - Entity extraction and relationship mapping
# 
# Features:
# - Legislative document relationship mapping
# - Government agency interaction networks
# - Legal citation networks and precedent tracking
# - Geographic jurisdiction relationships
# - Temporal legislative evolution tracking
# - Interactive graph visualization
# - Query interface for complex relationships
# - Export capabilities for academic research
# ============================================================================

cat("🕸️ Initializing Knowledge Graph Implementation - Week 10 Phase 3\n")
cat("🏛️ Legislative Relations • Entity Networks • Citation Analysis • Jurisdictional Mapping\n")

# Required packages
required_packages <- c(
  "igraph", "visNetwork", "networkD3", "dplyr", "stringr", 
  "jsonlite", "digest", "lubridate", "data.table"
)

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available, using fallbacks\n")
  } else {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
}

# KNOWLEDGE GRAPH CONFIGURATION
# =============================

KG_CONFIG <- list(
  # Graph structure settings
  structure = list(
    max_nodes = 10000,
    max_edges = 50000,
    min_edge_weight = 0.1,
    node_clustering_enabled = TRUE
  ),
  
  # Entity types
  entity_types = list(
    document = list(color = "#3498db", shape = "circle", size_factor = 1),
    law = list(color = "#e74c3c", shape = "diamond", size_factor = 1.5),
    agency = list(color = "#f39c12", shape = "square", size_factor = 1.2),
    person = list(color = "#9b59b6", shape = "triangle", size_factor = 0.8),
    place = list(color = "#2ecc71", shape = "circle", size_factor = 1),
    topic = list(color = "#1abc9c", shape = "star", size_factor = 0.9),
    date = list(color = "#95a5a6", shape = "circle", size_factor = 0.7)
  ),
  
  # Relationship types
  relationship_types = list(
    cites = list(color = "#e74c3c", weight = 2, type = "directed"),
    regulates = list(color = "#f39c12", weight = 1.5, type = "directed"),
    mentions = list(color = "#3498db", weight = 1, type = "undirected"),
    implements = list(color = "#2ecc71", weight = 1.8, type = "directed"),
    amends = list(color = "#9b59b6", weight = 2.5, type = "directed"),
    supersedes = list(color = "#e67e22", weight = 3, type = "directed"),
    issued_by = list(color = "#f39c12", weight = 1.2, type = "directed"),
    applies_to = list(color = "#2ecc71", weight = 1, type = "directed")
  ),
  
  # Performance settings
  performance = list(
    cache_enabled = TRUE,
    cache_ttl_hours = 48,
    incremental_update = TRUE,
    batch_size = 100
  ),
  
  # Visualization settings
  visualization = list(
    default_layout = "force_directed",
    interactive = TRUE,
    zoom_enabled = TRUE,
    clustering_threshold = 50
  )
)

# GRAPH STORAGE
# =============

# In-memory graph storage
knowledge_graph <- new.env()
knowledge_graph$nodes <- data.frame(
  id = character(),
  label = character(),
  type = character(),
  weight = numeric(),
  metadata = character(),
  created_at = as.POSIXct(character()),
  stringsAsFactors = FALSE
)

knowledge_graph$edges <- data.frame(
  from = character(),
  to = character(),
  type = character(),
  weight = numeric(),
  metadata = character(),
  created_at = as.POSIXct(character()),
  stringsAsFactors = FALSE
)

knowledge_graph$stats <- list(
  total_nodes = 0,
  total_edges = 0,
  last_updated = Sys.time(),
  version = 1
)

# ENTITY EXTRACTION AND PROCESSING
# =================================

# Extract entities from document
extract_document_entities <- function(document) {
  tryCatch({
    cat("🔍 Extracting entities from document:", document$id %||% "unknown", "\n")
    
    # Load AI services if available
    if (file.exists("R/ai/ai_services.R") && exists("ai_extract_entities")) {
      ai_entities <- ai_extract_entities(
        paste(document$titulo, document$ementa, document$texto, collapse = " "),
        entity_types = c("laws", "agencies", "places", "dates")
      )
    } else {
      ai_entities <- list()
    }
    
    # Enhanced entity extraction for Brazilian legal documents
    text <- paste(document$titulo %||% "", document$ementa %||% "", document$texto %||% "", collapse = " ")
    
    entities <- list()
    
    # Extract law references
    entities$laws <- extract_law_entities(text)
    
    # Extract government agencies
    entities$agencies <- extract_agency_entities(text)
    
    # Extract geographic entities
    entities$places <- extract_geographic_entities(text)
    
    # Extract dates and temporal references
    entities$dates <- extract_temporal_entities(text)
    
    # Extract topics and subjects
    entities$topics <- extract_topic_entities(text, document)
    
    # Extract people and authorities
    entities$people <- extract_person_entities(text)
    
    # Merge with AI-extracted entities if available
    if (length(ai_entities) > 0) {
      for (type in names(ai_entities)) {
        if (type %in% names(entities)) {
          entities[[type]] <- unique(c(entities[[type]], ai_entities[[type]]))
        } else {
          entities[[type]] <- ai_entities[[type]]
        }
      }
    }
    
    cat("✅ Extracted", length(unlist(entities)), "entities from document\n")
    return(entities)
    
  }, error = function(e) {
    cat("❌ Entity extraction error:", e$message, "\n")
    return(list())
  })
}

# Extract law references
extract_law_entities <- function(text) {
  law_patterns <- list(
    "Lei Federal" = "Lei\\s+(?:Federal\\s+)?(?:nº|n°|n\\.|número)?\\s*([0-9]{1,5}(?:\\.[0-9]{3})*(?:/[0-9]{4})?)",
    "Decreto" = "Decreto\\s+(?:nº|n°|n\\.|número)?\\s*([0-9]{1,5}(?:\\.[0-9]{3})*(?:/[0-9]{4})?)",
    "Resolução" = "Resolução\\s+(?:nº|n°|n\\.|número)?\\s*([0-9]{1,5}(?:\\.[0-9]{3})*(?:/[0-9]{4})?)",
    "Portaria" = "Portaria\\s+(?:nº|n°|n\\.|número)?\\s*([0-9]{1,5}(?:\\.[0-9]{3})*(?:/[0-9]{4})?)",
    "Instrução Normativa" = "Instrução\\s+Normativa\\s+(?:nº|n°|n\\.|número)?\\s*([0-9]{1,5}(?:\\.[0-9]{3})*(?:/[0-9]{4})?)",
    "Medida Provisória" = "Medida\\s+Provisória\\s+(?:nº|n°|n\\.|número)?\\s*([0-9]{1,5}(?:\\.[0-9]{3})*(?:/[0-9]{4})?)",
    "Constituição" = "Constituição\\s+(?:Federal)?",
    "Código Civil" = "Código\\s+Civil",
    "Código Penal" = "Código\\s+Penal",
    "CLT" = "(?:CLT|Consolidação\\s+das\\s+Leis\\s+do\\s+Trabalho)"
  )
  
  laws <- c()
  for (type in names(law_patterns)) {
    pattern <- law_patterns[[type]]
    matches <- str_extract_all(text, pattern, simplify = FALSE)[[1]]
    if (isTRUE(length(matches) > 0) && !all(is.na(matches))) {
      laws <- c(laws, paste(type, matches))
    }
  }
  
  return(unique(laws[!is.na(laws)]))
}

# Extract government agencies
extract_agency_entities <- function(text) {
  agencies <- list(
    # Transportation agencies
    "ANTT" = "(?:ANTT|Agência Nacional de Transportes Terrestres)",
    "ANTAQ" = "(?:ANTAQ|Agência Nacional de Transportes Aquaviários)",
    "ANAC" = "(?:ANAC|Agência Nacional de Aviação Civil)",
    "DNIT" = "(?:DNIT|Departamento Nacional de Infraestrutura de Transportes)",
    "DENATRAN" = "(?:DENATRAN|Departamento Nacional de Trânsito)",
    "CONTRAN" = "(?:CONTRAN|Conselho Nacional de Trânsito)",
    
    # Environmental agencies
    "IBAMA" = "(?:IBAMA|Instituto Brasileiro do Meio Ambiente)",
    "ICMBio" = "(?:ICMBio|Instituto Chico Mendes)",
    
    # Other regulatory agencies
    "ANVISA" = "(?:ANVISA|Agência Nacional de Vigilância Sanitária)",
    "ANP" = "(?:ANP|Agência Nacional do Petróleo)",
    "ANEEL" = "(?:ANEEL|Agência Nacional de Energia Elétrica)",
    
    # Ministries
    "Ministério dos Transportes" = "Ministério\\s+dos\\s+Transportes",
    "Ministério da Infraestrutura" = "Ministério\\s+da\\s+Infraestrutura",
    "Ministério do Meio Ambiente" = "Ministério\\s+do\\s+Meio\\s+Ambiente",
    
    # Courts and judicial bodies
    "STF" = "(?:STF|Supremo\\s+Tribunal\\s+Federal)",
    "STJ" = "(?:STJ|Superior\\s+Tribunal\\s+de\\s+Justiça)",
    "TST" = "(?:TST|Tribunal\\s+Superior\\s+do\\s+Trabalho)"
  )
  
  found_agencies <- c()
  for (agency_name in names(agencies)) {
    pattern <- agencies[[agency_name]]
    if (grepl(pattern, text, ignore.case = TRUE)) {
      found_agencies <- c(found_agencies, agency_name)
    }
  }
  
  return(unique(found_agencies))
}

# Extract geographic entities
extract_geographic_entities <- function(text) {
  # Brazilian states and federal district
  states <- list(
    "AC" = "(?:Acre|\\bAC\\b)", "AL" = "(?:Alagoas|\\bAL\\b)", "AP" = "(?:Amapá|\\bAP\\b)",
    "AM" = "(?:Amazonas|\\bAM\\b)", "BA" = "(?:Bahia|\\bBA\\b)", "CE" = "(?:Ceará|\\bCE\\b)",
    "DF" = "(?:Distrito Federal|\\bDF\\b)", "ES" = "(?:Espírito Santo|\\bES\\b)",
    "GO" = "(?:Goiás|\\bGO\\b)", "MA" = "(?:Maranhão|\\bMA\\b)", "MT" = "(?:Mato Grosso|\\bMT\\b)",
    "MS" = "(?:Mato Grosso do Sul|\\bMS\\b)", "MG" = "(?:Minas Gerais|\\bMG\\b)",
    "PA" = "(?:Pará|\\bPA\\b)", "PB" = "(?:Paraíba|\\bPB\\b)", "PR" = "(?:Paraná|\\bPR\\b)",
    "PE" = "(?:Pernambuco|\\bPE\\b)", "PI" = "(?:Piauí|\\bPI\\b)", "RJ" = "(?:Rio de Janeiro|\\bRJ\\b)",
    "RN" = "(?:Rio Grande do Norte|\\bRN\\b)", "RS" = "(?:Rio Grande do Sul|\\bRS\\b)",
    "RO" = "(?:Rondônia|\\bRO\\b)", "RR" = "(?:Roraima|\\bRR\\b)", "SC" = "(?:Santa Catarina|\\bSC\\b)",
    "SP" = "(?:São Paulo|\\bSP\\b)", "SE" = "(?:Sergipe|\\bSE\\b)", "TO" = "(?:Tocantins|\\bTO\\b)"
  )
  
  # Major cities
  cities <- c(
    "São Paulo", "Rio de Janeiro", "Brasília", "Salvador", "Fortaleza",
    "Belo Horizonte", "Manaus", "Curitiba", "Recife", "Porto Alegre",
    "Goiânia", "Belém", "Guarulhos", "Campinas", "São Luís", "São Gonçalo",
    "Maceió", "Duque de Caxias", "Nova Iguaçu", "Teresina"
  )
  
  places <- c()
  
  # Find states
  for (state in names(states)) {
    pattern <- states[[state]]
    if (grepl(pattern, text, ignore.case = TRUE)) {
      places <- c(places, state)
    }
  }
  
  # Find cities
  for (city in cities) {
    if (grepl(city, text, ignore.case = TRUE)) {
      places <- c(places, city)
    }
  }
  
  # Find regions
  regions <- c("Norte", "Nordeste", "Centro-Oeste", "Sudeste", "Sul")
  for (region in regions) {
    if (grepl(paste0("\\b", region, "\\b"), text, ignore.case = TRUE)) {
      places <- c(places, paste("Região", region))
    }
  }
  
  return(unique(places))
}

# Extract temporal entities
extract_temporal_entities <- function(text) {
  date_patterns <- list(
    "full_date" = "[0-9]{1,2}\\s+de\\s+[a-záêçõ]+\\s+de\\s+[0-9]{4}",
    "numeric_date" = "[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}",
    "iso_date" = "[0-9]{4}-[0-9]{2}-[0-9]{2}",
    "year" = "\\b[0-9]{4}\\b",
    "month_year" = "[a-záêçõ]+\\s+de\\s+[0-9]{4}"
  )
  
  dates <- c()
  for (type in names(date_patterns)) {
    pattern <- date_patterns[[type]]
    matches <- str_extract_all(text, pattern, simplify = FALSE)[[1]]
    if (isTRUE(length(matches) > 0) && !all(is.na(matches))) {
      dates <- c(dates, matches)
    }
  }
  
  return(unique(dates[!is.na(dates)]))
}

# Extract topic entities
extract_topic_entities <- function(text, document) {
  topic_keywords <- list(
    "Transporte Rodoviário" = c("rodoviário", "estrada", "rodovia", "veículo", "caminhão", "ônibus"),
    "Transporte Aquaviário" = c("aquaviário", "porto", "navegação", "embarcação", "navio", "barca"),
    "Aviação Civil" = c("aviação", "aeroporto", "aeronave", "voo", "piloto", "controlador"),
    "Segurança no Transporte" = c("segurança", "acidente", "sinistro", "prevenção", "emergência"),
    "Meio Ambiente" = c("ambiental", "sustentabilidade", "emissão", "poluição", "conservação"),
    "Infraestrutura" = c("infraestrutura", "obra", "construção", "modernização", "manutenção"),
    "Regulamentação" = c("regulamento", "norma", "procedimento", "padrão", "especificação"),
    "Fiscalização" = c("fiscalização", "autuação", "multa", "penalidade", "sanção"),
    "Licenciamento" = c("licenciamento", "autorização", "permissão", "concessão", "habilitação"),
    "Tarifação" = c("tarifa", "preço", "cobrança", "pagamento", "taxa"),
    "Qualidade de Serviço" = c("qualidade", "atendimento", "satisfação", "reclamação", "melhoria"),
    "Acessibilidade" = c("acessibilidade", "deficiente", "mobilidade", "inclusão", "universal")
  )
  
  text_lower <- tolower(text)
  topics <- c()
  
  for (topic in names(topic_keywords)) {
    keywords <- topic_keywords[[topic]]
    matches <- sum(sapply(keywords, function(k) {
      count <- length(gregexpr(k, text_lower)[[1]])
      if (count == 1 && gregexpr(k, text_lower)[[1]][1] == -1) count <- 0
      return(count)
    }))
    
    if (matches > 0) {
      topics <- c(topics, topic)
    }
  }
  
  # Add document type as topic
  if (!is.null(document$species)) {
    topics <- c(topics, document$species)
  }
  
  return(unique(topics))
}

# Extract person entities
extract_person_entities <- function(text) {
  # Common Brazilian names and titles
  title_patterns <- c(
    "(?:Dr|Dra|Doutor|Doutora)\\.?\\s+[A-ZÁÊÇÕ][a-záêçõ]+(?:\\s+[A-ZÁÊÇÕ][a-záêçõ]+)*",
    "(?:Prof|Professor|Professora)\\.?\\s+[A-ZÁÊÇÕ][a-záêçõ]+(?:\\s+[A-ZÁÊÇÕ][a-záêçõ]+)*",
    "(?:Ministro|Ministra)\\s+[A-ZÁÊÇÕ][a-záêçõ]+(?:\\s+[A-ZÁÊÇÕ][a-záêçõ]+)*",
    "(?:Diretor|Diretora)\\s+[A-ZÁÊÇÕ][a-záêçõ]+(?:\\s+[A-ZÁÊÇÕ][a-záêçõ]+)*",
    "(?:Presidente|Presidenta)\\s+[A-ZÁÊÇÕ][a-záêçõ]+(?:\\s+[A-ZÁÊÇÕ][a-záêçõ]+)*"
  )
  
  people <- c()
  for (pattern in title_patterns) {
    matches <- str_extract_all(text, pattern, simplify = FALSE)[[1]]
    if (isTRUE(length(matches) > 0) && !all(is.na(matches))) {
      people <- c(people, matches)
    }
  }
  
  return(unique(people[!is.na(people)]))
}

# GRAPH CONSTRUCTION
# ==================

# Add node to knowledge graph
add_node <- function(id, label, type, weight = 1, metadata = list()) {
  tryCatch({
    # Check if node already exists
    if (id %in% knowledge_graph$nodes$id) {
      # Update existing node
      idx <- which(knowledge_graph$nodes$id == id)
      knowledge_graph$nodes$weight[idx] <- knowledge_graph$nodes$weight[idx] + weight
      knowledge_graph$nodes$metadata[idx] <- toJSON(metadata, auto_unbox = TRUE)
      cat("📝 Updated existing node:", id, "\n")
    } else {
      # Add new node
      new_node <- data.frame(
        id = id,
        label = label,
        type = type,
        weight = weight,
        metadata = toJSON(metadata, auto_unbox = TRUE),
        created_at = Sys.time(),
        stringsAsFactors = FALSE
      )
      
      knowledge_graph$nodes <- rbind(knowledge_graph$nodes, new_node)
      knowledge_graph$stats$total_nodes <- knowledge_graph$stats$total_nodes + 1
      cat("➕ Added new node:", id, "(", type, ")\n")
    }
    
    knowledge_graph$stats$last_updated <- Sys.time()
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error adding node:", e$message, "\n")
    return(FALSE)
  })
}

# Add edge to knowledge graph
add_edge <- function(from, to, type, weight = 1, metadata = list()) {
  tryCatch({
    # Check if edge already exists
    existing_edge <- knowledge_graph$edges[
      knowledge_graph$edges$from == from & 
      knowledge_graph$edges$to == to & 
      knowledge_graph$edges$type == type, 
    ]
    
    if (nrow(existing_edge) > 0) {
      # Update existing edge
      idx <- which(
        knowledge_graph$edges$from == from & 
        knowledge_graph$edges$to == to & 
        knowledge_graph$edges$type == type
      )[1]
      knowledge_graph$edges$weight[idx] <- knowledge_graph$edges$weight[idx] + weight
      knowledge_graph$edges$metadata[idx] <- toJSON(metadata, auto_unbox = TRUE)
      cat("📝 Updated existing edge:", from, "->", to, "(", type, ")\n")
    } else {
      # Add new edge
      new_edge <- data.frame(
        from = from,
        to = to,
        type = type,
        weight = weight,
        metadata = toJSON(metadata, auto_unbox = TRUE),
        created_at = Sys.time(),
        stringsAsFactors = FALSE
      )
      
      knowledge_graph$edges <- rbind(knowledge_graph$edges, new_edge)
      knowledge_graph$stats$total_edges <- knowledge_graph$stats$total_edges + 1
      cat("🔗 Added new edge:", from, "->", to, "(", type, ")\n")
    }
    
    knowledge_graph$stats$last_updated <- Sys.time()
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error adding edge:", e$message, "\n")
    return(FALSE)
  })
}

# Build knowledge graph from documents
build_knowledge_graph_from_documents <- function(documents, incremental = TRUE) {
  tryCatch({
    cat("🏗️ Building knowledge graph from", length(documents), "documents...\n")
    
    if (!incremental) {
      # Clear existing graph
      knowledge_graph$nodes <- knowledge_graph$nodes[0, ]
      knowledge_graph$edges <- knowledge_graph$edges[0, ]
      knowledge_graph$stats$total_nodes <- 0
      knowledge_graph$stats$total_edges <- 0
      cat("🗑️ Cleared existing graph for full rebuild\n")
    }
    
    # Process documents in batches
    batch_size <- KG_CONFIG$performance$batch_size
    num_batches <- ceiling(length(documents) / batch_size)
    
    for (batch_idx in 1:num_batches) {
      start_idx <- (batch_idx - 1) * batch_size + 1
      end_idx <- min(batch_idx * batch_size, length(documents))
      batch_docs <- documents[start_idx:end_idx]
      
      cat("🔄 Processing batch", batch_idx, "of", num_batches, "(", length(batch_docs), "documents)\n")
      
      for (i in seq_along(batch_docs)) {
        doc <- batch_docs[[i]]
        process_document_for_graph(doc)
      }
      
      # Memory cleanup
      if (batch_idx %% 5 == 0) {
        gc()
      }
    }
    
    # Update version
    knowledge_graph$stats$version <- knowledge_graph$stats$version + 1
    knowledge_graph$stats$last_updated <- Sys.time()
    
    cat("✅ Knowledge graph construction completed\n")
    cat("📊 Total nodes:", knowledge_graph$stats$total_nodes, "\n")
    cat("📊 Total edges:", knowledge_graph$stats$total_edges, "\n")
    
    return(get_graph_summary())
    
  }, error = function(e) {
    cat("❌ Graph construction error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Process single document for graph
process_document_for_graph <- function(document) {
  tryCatch({
    doc_id <- paste0("doc_", document$id %||% digest(document$titulo %||% "unknown"))
    
    # Add document node
    add_node(
      id = doc_id,
      label = document$titulo %||% "Untitled Document",
      type = "document",
      weight = 1,
      metadata = list(
        species = document$species,
        data_publicacao = document$data_publicacao,
        estado = document$estado,
        municipio = document$municipio
      )
    )
    
    # Extract entities
    entities <- extract_document_entities(document)
    
    # Process each entity type
    for (entity_type in names(entities)) {
      entity_list <- entities[[entity_type]]
      
      for (entity_value in entity_list) {
        if (!isTRUE(is.null(entity_value)) && !isTRUE(is.na(entity_value)) && nchar(entity_value) > 0) {
          entity_id <- paste0(entity_type, "_", digest(entity_value))
          
          # Map entity type to graph type
          graph_type <- switch(entity_type,
            "laws" = "law",
            "agencies" = "agency",
            "places" = "place",
            "dates" = "date",
            "topics" = "topic",
            "people" = "person",
            entity_type
          )
          
          # Add entity node
          add_node(
            id = entity_id,
            label = entity_value,
            type = graph_type,
            weight = 1,
            metadata = list(original_type = entity_type)
          )
          
          # Add relationship edge
          relationship_type <- switch(entity_type,
            "laws" = "cites",
            "agencies" = "issued_by",
            "places" = "applies_to",
            "dates" = "published_on",
            "topics" = "discusses",
            "people" = "authored_by",
            "mentions"
          )
          
          add_edge(
            from = doc_id,
            to = entity_id,
            type = relationship_type,
            weight = 1,
            metadata = list(extraction_method = "automated")
          )
        }
      }
    }
    
    # Add inter-entity relationships
    add_inter_entity_relationships(entities, doc_id)
    
  }, error = function(e) {
    cat("❌ Error processing document for graph:", e$message, "\n")
  })
}

# Add relationships between entities
add_inter_entity_relationships <- function(entities, doc_id) {
  tryCatch({
    # Laws regulate agencies
    if ("laws" %in% names(entities) && "agencies" %in% names(entities)) {
      for (law in entities$laws) {
        for (agency in entities$agencies) {
          law_id <- paste0("laws_", digest(law))
          agency_id <- paste0("agencies_", digest(agency))
          
          add_edge(
            from = law_id,
            to = agency_id,
            type = "regulates",
            weight = 0.5,
            metadata = list(inferred = TRUE, source_doc = doc_id)
          )
        }
      }
    }
    
    # Agencies operate in places
    if ("agencies" %in% names(entities) && "places" %in% names(entities)) {
      for (agency in entities$agencies) {
        for (place in entities$places) {
          agency_id <- paste0("agencies_", digest(agency))
          place_id <- paste0("places_", digest(place))
          
          add_edge(
            from = agency_id,
            to = place_id,
            type = "operates_in",
            weight = 0.3,
            metadata = list(inferred = TRUE, source_doc = doc_id)
          )
        }
      }
    }
    
    # Topics relate to places
    if ("topics" %in% names(entities) && "places" %in% names(entities)) {
      for (topic in entities$topics) {
        for (place in entities$places) {
          topic_id <- paste0("topics_", digest(topic))
          place_id <- paste0("places_", digest(place))
          
          add_edge(
            from = topic_id,
            to = place_id,
            type = "relevant_to",
            weight = 0.2,
            metadata = list(inferred = TRUE, source_doc = doc_id)
          )
        }
      }
    }
    
  }, error = function(e) {
    cat("❌ Error adding inter-entity relationships:", e$message, "\n")
  })
}

# GRAPH ANALYSIS
# ==============

# Get graph summary statistics
get_graph_summary <- function() {
  tryCatch({
    if (nrow(knowledge_graph$nodes) == 0) {
      return(list(
        total_nodes = 0,
        total_edges = 0,
        message = "Graph is empty"
      ))
    }
    
    # Create igraph object for analysis
    g <- graph_from_data_frame(
      d = knowledge_graph$edges[, c("from", "to", "weight", "type")],
      vertices = knowledge_graph$nodes[, c("id", "label", "type", "weight")],
      directed = TRUE
    )
    
    # Calculate metrics
    node_types <- table(knowledge_graph$nodes$type)
    edge_types <- table(knowledge_graph$edges$type)
    
    # Network metrics
    density <- edge_density(g)
    diameter <- if (is.connected(g)) diameter(g) else NA
    avg_degree <- mean(degree(g))
    
    # Centrality measures (for top nodes)
    top_n <- min(10, vcount(g))
    betweenness_centrality <- betweenness(g)
    degree_centrality <- degree(g)
    
    top_betweenness <- names(sort(betweenness_centrality, decreasing = TRUE)[1:top_n])
    top_degree <- names(sort(degree_centrality, decreasing = TRUE)[1:top_n])
    
    summary <- list(
      overview = list(
        total_nodes = knowledge_graph$stats$total_nodes,
        total_edges = knowledge_graph$stats$total_edges,
        graph_density = round(density, 4),
        average_degree = round(avg_degree, 2),
        diameter = diameter,
        is_connected = is.connected(g),
        last_updated = knowledge_graph$stats$last_updated,
        version = knowledge_graph$stats$version
      ),
      
      node_distribution = as.list(node_types),
      edge_distribution = as.list(edge_types),
      
      top_nodes = list(
        by_betweenness = top_betweenness,
        by_degree = top_degree
      ),
      
      components = list(
        count = components(g)$no,
        largest_size = max(components(g)$csize)
      )
    )
    
    return(summary)
    
  }, error = function(e) {
    cat("❌ Error generating graph summary:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Query graph for relationships
query_graph <- function(entity_id, relationship_types = NULL, max_depth = 2, direction = "both") {
  tryCatch({
    cat("🔍 Querying graph for entity:", entity_id, "\n")
    
    if (nrow(knowledge_graph$edges) == 0) {
      return(list(message = "Graph is empty"))
    }
    
    # Create igraph object
    g <- graph_from_data_frame(
      d = knowledge_graph$edges[, c("from", "to", "weight", "type")],
      vertices = knowledge_graph$nodes[, c("id", "label", "type", "weight")],
      directed = TRUE
    )
    
    # Check if entity exists
    if (!entity_id %in% V(g)$name) {
      return(list(error = "Entity not found in graph"))
    }
    
    # Get neighbors within max_depth
    if (direction == "out") {
      neighbors <- ego(g, order = max_depth, nodes = entity_id, mode = "out")[[1]]
    } else if (direction == "in") {
      neighbors <- ego(g, order = max_depth, nodes = entity_id, mode = "in")[[1]]
    } else {
      neighbors <- ego(g, order = max_depth, nodes = entity_id, mode = "all")[[1]]
    }
    
    neighbor_ids <- V(g)$name[neighbors]
    
    # Get subgraph
    subgraph <- induced_subgraph(g, neighbors)
    
    # Extract nodes and edges
    result_nodes <- knowledge_graph$nodes[knowledge_graph$nodes$id %in% neighbor_ids, ]
    
    # Get edges within subgraph
    result_edges <- knowledge_graph$edges[
      knowledge_graph$edges$from %in% neighbor_ids & 
      knowledge_graph$edges$to %in% neighbor_ids,
    ]
    
    # Filter by relationship types if specified
    if (!is.null(relationship_types)) {
      result_edges <- result_edges[result_edges$type %in% relationship_types, ]
    }
    
    result <- list(
      query = list(
        entity_id = entity_id,
        max_depth = max_depth,
        direction = direction,
        relationship_types = relationship_types
      ),
      nodes = result_nodes,
      edges = result_edges,
      metrics = list(
        total_nodes = nrow(result_nodes),
        total_edges = nrow(result_edges),
        subgraph_density = if (nrow(result_nodes) > 1) edge_density(subgraph) else 0
      )
    )
    
    cat("✅ Query completed:", nrow(result_nodes), "nodes,", nrow(result_edges), "edges\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Graph query error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# VISUALIZATION
# =============

# Generate interactive visualization
generate_graph_visualization <- function(query_result = NULL, layout = "force_directed") {
  tryCatch({
    cat("🎨 Generating graph visualization...\n")
    
    # Use query result or full graph
    if (!isTRUE(is.null(query_result)) && "nodes" %in% names(query_result)) {
      nodes_data <- query_result$nodes
      edges_data <- query_result$edges
    } else {
      nodes_data <- knowledge_graph$nodes
      edges_data <- knowledge_graph$edges
    }
    
    if (nrow(nodes_data) == 0) {
      return(list(error = "No data to visualize"))
    }
    
    # Prepare nodes for visNetwork
    vis_nodes <- data.frame(
      id = nodes_data$id,
      label = nodes_data$label,
      group = nodes_data$type,
      value = nodes_data$weight,
      title = paste0("Type: ", nodes_data$type, "<br>Weight: ", nodes_data$weight),
      stringsAsFactors = FALSE
    )
    
    # Add visual properties based on type
    for (i in 1:nrow(vis_nodes)) {
      node_type <- vis_nodes$group[i]
      if (node_type %in% names(KG_CONFIG$entity_types)) {
        vis_nodes$color[i] <- KG_CONFIG$entity_types[[node_type]]$color
        vis_nodes$shape[i] <- KG_CONFIG$entity_types[[node_type]]$shape
        vis_nodes$size[i] <- vis_nodes$value[i] * KG_CONFIG$entity_types[[node_type]]$size_factor * 10
      } else {
        vis_nodes$color[i] <- "#95a5a6"
        vis_nodes$shape[i] <- "circle"
        vis_nodes$size[i] <- vis_nodes$value[i] * 10
      }
    }
    
    # Prepare edges for visNetwork
    if (nrow(edges_data) > 0) {
      vis_edges <- data.frame(
        from = edges_data$from,
        to = edges_data$to,
        label = edges_data$type,
        value = edges_data$weight,
        title = paste0("Type: ", edges_data$type, "<br>Weight: ", edges_data$weight),
        stringsAsFactors = FALSE
      )
      
      # Add visual properties based on relationship type
      for (i in 1:nrow(vis_edges)) {
        edge_type <- vis_edges$label[i]
        if (edge_type %in% names(KG_CONFIG$relationship_types)) {
          vis_edges$color[i] <- KG_CONFIG$relationship_types[[edge_type]]$color
          vis_edges$width[i] <- vis_edges$value[i] * KG_CONFIG$relationship_types[[edge_type]]$weight
          
          if (KG_CONFIG$relationship_types[[edge_type]]$type == "directed") {
            vis_edges$arrows[i] <- "to"
          }
        } else {
          vis_edges$color[i] <- "#95a5a6"
          vis_edges$width[i] <- vis_edges$value[i]
        }
      }
    } else {
      vis_edges <- data.frame()
    }
    
    # Generate visualization using visNetwork if available
    if (requireNamespace("visNetwork", quietly = TRUE)) {
      vis <- visNetwork(vis_nodes, vis_edges) %>%
        visOptions(highlightNearest = TRUE, nodesIdSelection = TRUE) %>%
        visInteraction(navigationButtons = TRUE) %>%
        visLayout(randomSeed = 123)
      
      cat("✅ Interactive visualization generated\n")
      return(list(
        visualization = vis,
        nodes = vis_nodes,
        edges = vis_edges,
        type = "visNetwork"
      ))
    } else {
      cat("⚠️ visNetwork not available, returning data for external visualization\n")
      return(list(
        nodes = vis_nodes,
        edges = vis_edges,
        type = "data_only"
      ))
    }
    
  }, error = function(e) {
    cat("❌ Visualization error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# EXPORT AND PERSISTENCE
# ======================

# Export graph data
export_graph_data <- function(format = "json", include_metadata = TRUE) {
  tryCatch({
    cat("💾 Exporting graph data in", format, "format...\n")
    
    export_data <- list(
      metadata = list(
        export_timestamp = Sys.time(),
        graph_version = knowledge_graph$stats$version,
        total_nodes = knowledge_graph$stats$total_nodes,
        total_edges = knowledge_graph$stats$total_edges,
        format = format
      ),
      nodes = knowledge_graph$nodes,
      edges = knowledge_graph$edges,
      summary = get_graph_summary()
    )
    
    if (!include_metadata) {
      export_data$metadata <- NULL
      export_data$summary <- NULL
    }
    
    if (format == "json") {
      result <- toJSON(export_data, pretty = TRUE)
    } else if (format == "csv") {
      # For CSV, return list of data frames
      result <- list(
        nodes = knowledge_graph$nodes,
        edges = knowledge_graph$edges
      )
    } else if (format == "graphml") {
      # For GraphML, create igraph object and export
      if (requireNamespace("igraph", quietly = TRUE) && nrow(knowledge_graph$edges) > 0) {
        g <- graph_from_data_frame(
          d = knowledge_graph$edges[, c("from", "to", "weight", "type")],
          vertices = knowledge_graph$nodes[, c("id", "label", "type", "weight")],
          directed = TRUE
        )
        
        temp_file <- tempfile(fileext = ".graphml")
        write_graph(g, temp_file, format = "graphml")
        result <- readLines(temp_file)
        unlink(temp_file)
      } else {
        result <- NULL
      }
    } else {
      result <- export_data
    }
    
    cat("✅ Graph data exported successfully\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Export error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Initialize knowledge graph system
init_knowledge_graph <- function() {
  cat("🕸️ Initializing Knowledge Graph System...\n")
  cat("📊 Maximum nodes:", KG_CONFIG$structure$max_nodes, "\n")
  cat("📊 Maximum edges:", KG_CONFIG$structure$max_edges, "\n")
  cat("🎨 Entity types:", length(KG_CONFIG$entity_types), "\n")
  cat("🔗 Relationship types:", length(KG_CONFIG$relationship_types), "\n")
  cat("💾 Caching enabled:", KG_CONFIG$performance$cache_enabled, "\n")
  
  return(TRUE)
}

# Export knowledge graph functions
KG_FUNCTIONS <- list(
  extract_document_entities = extract_document_entities,
  add_node = add_node,
  add_edge = add_edge,
  build_knowledge_graph_from_documents = build_knowledge_graph_from_documents,
  get_graph_summary = get_graph_summary,
  query_graph = query_graph,
  generate_graph_visualization = generate_graph_visualization,
  export_graph_data = export_graph_data,
  init_knowledge_graph = init_knowledge_graph
)

# Initialize on load
init_knowledge_graph()

cat("✅ Knowledge Graph Implementation ready for legislative relationship analysis\n")