# ============================================================================
# AMENDMENT PATTERN ANALYSIS MODULE
# ============================================================================
#
# Comprehensive analysis of amendment patterns in Brazilian legislative documents
# Tracks how laws are modified over time, identifies hotspots, and detects cascades
#
# Author: Monitor Legislativo Analytics Team
# Date: 2025-01-13
# Version: 1.0
# ============================================================================

library(dplyr)
library(tidyr)
library(stringr)
library(DBI)
library(lubridate)
library(igraph)

# ============================================================================
# PORTUGUESE AMENDMENT KEYWORDS
# ============================================================================

# Define Brazilian legislative amendment patterns
AMENDMENT_KEYWORDS <- list(
  # Amendment verbs
  modifies = c("altera", "modifica", "altera dispositivos", "altera a lei",
               "altera o art", "altera os arts", "altera artigo"),

  # Revocation verbs
  revokes = c("revoga", "revoga o art", "revoga os arts", "revoga a lei",
              "revoga dispositivos", "cancela", "anula"),

  # Addition verbs
  adds = c("acrescenta", "inclui", "adiciona", "insere", "acresce",
           "introduz", "incorpora"),

  # Repeal verbs
  repeals = c("derroga", "abroga", "suprime", "elimina"),

  # Substitution verbs
  substitutes = c("substitui", "troca", "muda", "transforma"),

  # Legal references
  references = c("Lei n[ºo°]", "Lei n\\.?\\s*\\d+", "Decreto n[ºo°]",
                "Medida Provis[óo]ria", "art\\.", "artigo", "§", "paragrafo",
                "inciso", "al[íi]nea"),

  # Specific amendment types
  complementary = c("Lei Complementar", "lei complementar"),
  ordinary = c("Lei Ordin[áa]ria", "lei ordin[áa]ria")
)

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

#' Identify Amendment Documents
#'
#' Extract documents that contain amendment language
#'
#' @param db_connection DBI connection to PostgreSQL database
#' @param year_range Optional vector c(start_year, end_year)
#' @param jurisdiction_filter Optional jurisdiction level filter
#' @return Data frame with amendment documents
#' @export
identify_amendments <- function(db_connection,
                               year_range = NULL,
                               jurisdiction_filter = NULL) {

  if (is.null(db_connection)) {
    warning("No database connection provided")
    return(data.frame())
  }

  tryCatch({
    # Build base query
    query <- "
      SELECT
        d.id,
        d.urn,
        d.titulo,
        d.tipo,
        d.ano,
        d.estado,
        d.nivel,
        d.municipio,
        d.data_publicacao,
        d.conteudo,
        COALESCE(d.texto_completo, d.conteudo, '') AS texto
      FROM documents d
      WHERE 1=1
    "

    params <- list()
    param_idx <- 1

    # Add year filter
    if (!is.null(year_range) && length(year_range) == 2) {
      query <- paste0(query, sprintf(" AND d.ano >= $%d AND d.ano <= $%d", param_idx, param_idx + 1))
      params[[param_idx]] <- year_range[1]
      params[[param_idx + 1]] <- year_range[2]
      param_idx <- param_idx + 2
    }

    # Add jurisdiction filter
    if (!is.null(jurisdiction_filter)) {
      query <- paste0(query, sprintf(" AND d.nivel = $%d", param_idx))
      params[[param_idx]] <- jurisdiction_filter
      param_idx <- param_idx + 1
    }

    # Get documents
    docs <- if (length(params) > 0) {
      DBI::dbGetQuery(db_connection, query, params)
    } else {
      DBI::dbGetQuery(db_connection, query)
    }

    if (nrow(docs) == 0) {
      return(data.frame())
    }

    # Identify amendment patterns in text
    docs <- docs %>%
      mutate(
        # Check for modification keywords
        is_modification = str_detect(tolower(texto),
          paste(AMENDMENT_KEYWORDS$modifies, collapse = "|")),

        # Check for revocation keywords
        is_revocation = str_detect(tolower(texto),
          paste(AMENDMENT_KEYWORDS$revokes, collapse = "|")),

        # Check for addition keywords
        is_addition = str_detect(tolower(texto),
          paste(AMENDMENT_KEYWORDS$adds, collapse = "|")),

        # Check for substitution keywords
        is_substitution = str_detect(tolower(texto),
          paste(AMENDMENT_KEYWORDS$substitutes, collapse = "|")),

        # Check for legal references (Lei nº, art., etc.)
        has_legal_ref = str_detect(texto,
          paste(AMENDMENT_KEYWORDS$references, collapse = "|")),

        # Overall amendment flag
        is_amendment = (is_modification | is_revocation | is_addition | is_substitution) & has_legal_ref
      )

    # Extract referenced law numbers
    docs <- docs %>%
      mutate(
        referenced_laws = extract_referenced_laws(texto)
      )

    # Filter to only amendments
    amendments <- docs %>%
      filter(is_amendment) %>%
      mutate(
        amendment_type = case_when(
          is_revocation ~ "Revogação",
          is_substitution ~ "Substituição",
          is_addition ~ "Adição",
          is_modification ~ "Modificação",
          TRUE ~ "Outro"
        )
      )

    # Add metadata
    amendments <- amendments %>%
      mutate(
        extracted_date = Sys.time(),
        total_amendments = n()
      )

    return(amendments)

  }, error = function(e) {
    warning("Error identifying amendments: ", e$message)
    return(data.frame())
  })
}


#' Extract Referenced Laws from Text
#'
#' Extract law numbers and types from legal text
#'
#' @param text Character vector of legal text
#' @return Character vector of comma-separated law references
extract_referenced_laws <- function(text) {

  sapply(text, function(t) {
    if (is.na(t) || t == "") return(NA_character_)

    # Extract Lei patterns
    lei_pattern <- "Lei n[ºo°]?\\s*(\\d+(?:[.,]\\d+)?)"
    leis <- str_extract_all(t, lei_pattern)[[1]]

    # Extract Decreto patterns
    decreto_pattern <- "Decreto n[ºo°]?\\s*(\\d+(?:[.,]\\d+)?)"
    decretos <- str_extract_all(t, decreto_pattern)[[1]]

    # Combine
    refs <- c(leis, decretos)

    if (length(refs) > 0) {
      return(paste(unique(refs), collapse = "; "))
    } else {
      return(NA_character_)
    }
  }, USE.NAMES = FALSE)
}


#' Build Amendment Timeline for a Document
#'
#' Track the complete modification history of a specific law
#'
#' @param db_connection DBI connection
#' @param doc_id Integer document ID or URN string
#' @param max_depth Maximum depth of amendment chain to follow
#' @return List with timeline data and network structure
#' @export
build_amendment_timeline <- function(db_connection, doc_id, max_depth = 10) {

  if (is.null(db_connection)) {
    stop("Database connection required")
  }

  tryCatch({
    # Get focal document
    focal_doc <- if (is.character(doc_id)) {
      DBI::dbGetQuery(db_connection,
        "SELECT * FROM documents WHERE urn = $1", list(doc_id))
    } else {
      DBI::dbGetQuery(db_connection,
        "SELECT * FROM documents WHERE id = $1", list(doc_id))
    }

    if (nrow(focal_doc) == 0) {
      stop("Document not found")
    }

    # Extract law number from title or URN
    focal_law_num <- extract_law_number(focal_doc$titulo[1])
    if (is.na(focal_law_num)) {
      focal_law_num <- extract_law_number(focal_doc$urn[1])
    }

    # Find all amendments that reference this law
    amendments_to <- identify_amendments_to_law(db_connection, focal_law_num, focal_doc$tipo[1])

    # Find all amendments made by this law
    amendments_from <- identify_amendments_from_law(db_connection, focal_doc$id)

    # Build timeline
    timeline <- bind_rows(
      amendments_to %>% mutate(direction = "amends_focal"),
      amendments_from %>% mutate(direction = "focal_amends")
    ) %>%
      arrange(ano, data_publicacao)

    # Build network structure
    network <- build_amendment_network(
      focal_doc = focal_doc,
      amendments_to = amendments_to,
      amendments_from = amendments_from
    )

    # Calculate statistics
    stats <- list(
      focal_document = focal_doc,
      focal_law_number = focal_law_num,
      total_amendments_to = nrow(amendments_to),
      total_amendments_from = nrow(amendments_from),
      year_first_amendment = if(nrow(timeline) > 0) min(timeline$ano, na.rm = TRUE) else NA,
      year_last_amendment = if(nrow(timeline) > 0) max(timeline$ano, na.rm = TRUE) else NA,
      amendment_span_years = if(nrow(timeline) > 0) {
        max(timeline$ano, na.rm = TRUE) - min(timeline$ano, na.rm = TRUE)
      } else 0,
      amendment_frequency = if(nrow(timeline) > 0 &&
        max(timeline$ano, na.rm = TRUE) - min(timeline$ano, na.rm = TRUE) > 0) {
        nrow(timeline) / (max(timeline$ano, na.rm = TRUE) - min(timeline$ano, na.rm = TRUE))
      } else 0
    )

    return(list(
      focal = focal_doc,
      timeline = timeline,
      network = network,
      statistics = stats
    ))

  }, error = function(e) {
    warning("Error building amendment timeline: ", e$message)
    return(NULL)
  })
}


#' Identify Amendments TO a Specific Law
#'
#' Find all documents that amend a given law
#'
#' @param db_connection DBI connection
#' @param law_number Law number to search for
#' @param law_type Type of law (Lei, Decreto, etc.)
#' @return Data frame of amending documents
identify_amendments_to_law <- function(db_connection, law_number, law_type) {

  if (is.na(law_number)) {
    return(data.frame())
  }

  # Build search pattern
  search_pattern <- sprintf("%%Lei n[ºo°]?\\s*%s%%", law_number)
  if (!is.na(law_type) && law_type != "") {
    search_pattern <- sprintf("%%%s n[ºo°]?\\s*%s%%", law_type, law_number)
  }

  query <- "
    SELECT d.*,
           COALESCE(d.texto_completo, d.conteudo, '') AS texto
    FROM documents d
    WHERE (COALESCE(d.texto_completo, d.conteudo, '') ILIKE $1
           OR d.titulo ILIKE $1)
      AND (LOWER(COALESCE(d.texto_completo, d.conteudo, '')) ~ '(altera|modifica|revoga)'
           OR LOWER(d.titulo) ~ '(altera|modifica|revoga)')
  "

  result <- DBI::dbGetQuery(db_connection, query, list(search_pattern))
  return(result)
}


#' Identify Amendments FROM a Specific Law
#'
#' Find all laws that are amended by a given document
#'
#' @param db_connection DBI connection
#' @param doc_id Document ID
#' @return Data frame of amended laws
identify_amendments_from_law <- function(db_connection, doc_id) {

  # Get the amending document
  doc <- DBI::dbGetQuery(db_connection,
    "SELECT * FROM documents WHERE id = $1", list(doc_id))

  if (nrow(doc) == 0) {
    return(data.frame())
  }

  # Extract referenced laws
  texto <- doc$texto_completo[1]
  if (is.na(texto) || texto == "") {
    texto <- doc$conteudo[1]
  }

  refs <- extract_referenced_laws(texto)

  if (is.na(refs)) {
    return(data.frame())
  }

  # Parse individual references
  ref_list <- str_split(refs, ";\\s*")[[1]]

  # Search for each referenced law
  result <- data.frame()
  for (ref in ref_list) {
    pattern <- sprintf("%%%s%%", ref)
    found <- DBI::dbGetQuery(db_connection,
      "SELECT * FROM documents WHERE titulo ILIKE $1 OR urn ILIKE $1 LIMIT 5",
      list(pattern))

    if (nrow(found) > 0) {
      result <- bind_rows(result, found)
    }
  }

  return(result %>% distinct())
}


#' Extract Law Number from Text
#'
#' Extract the primary law number from title or URN
#'
#' @param text Character string
#' @return Character law number or NA
extract_law_number <- function(text) {

  if (is.na(text) || text == "") return(NA_character_)

  # Try to extract number from patterns like "Lei nº 1234" or "lei:1234"
  patterns <- c(
    "Lei n[ºo°]?\\s*(\\d+(?:[.,]\\d+)?)",
    "Decreto n[ºo°]?\\s*(\\d+(?:[.,]\\d+)?)",
    ":lei:(\\d{4}-\\d{2}-\\d{2});(\\d+)",
    ";(\\d+)$"
  )

  for (pattern in patterns) {
    match <- str_match(text, pattern)
    if (!is.na(match[1])) {
      # Return the last captured group
      return(match[length(match)])
    }
  }

  return(NA_character_)
}


#' Detect Amendment Hotspots
#'
#' Identify the most frequently amended laws
#'
#' @param db_connection DBI connection
#' @param min_amendments Minimum number of amendments to be considered a hotspot
#' @param top_n Return top N hotspots
#' @return Data frame with hotspot analysis
#' @export
detect_amendment_hotspots <- function(db_connection,
                                     min_amendments = 3,
                                     top_n = 20) {

  if (is.null(db_connection)) {
    stop("Database connection required")
  }

  tryCatch({
    # Get all amendments
    amendments <- identify_amendments(db_connection)

    if (nrow(amendments) == 0) {
      return(data.frame())
    }

    # Extract and count referenced laws
    ref_counts <- amendments %>%
      filter(!is.na(referenced_laws)) %>%
      mutate(refs = str_split(referenced_laws, ";\\s*")) %>%
      unnest(refs) %>%
      count(refs, sort = TRUE, name = "amendment_count") %>%
      filter(amendment_count >= min_amendments) %>%
      head(top_n)

    # Enrich with document details
    hotspots <- ref_counts %>%
      rowwise() %>%
      mutate(
        # Try to find the original document
        original_doc = list(find_law_by_reference(db_connection, refs))
      ) %>%
      ungroup()

    # Extract details from found documents
    hotspots <- hotspots %>%
      mutate(
        doc_found = map_lgl(original_doc, ~nrow(.x) > 0),
        doc_id = map_int(original_doc, ~if(nrow(.x) > 0) .x$id[1] else NA_integer_),
        doc_title = map_chr(original_doc, ~if(nrow(.x) > 0) .x$titulo[1] else NA_character_),
        doc_year = map_int(original_doc, ~if(nrow(.x) > 0) .x$ano[1] else NA_integer_),
        doc_type = map_chr(original_doc, ~if(nrow(.x) > 0) .x$tipo[1] else NA_character_)
      ) %>%
      select(-original_doc)

    # Calculate hotspot metrics
    hotspots <- hotspots %>%
      mutate(
        hotspot_rank = row_number(),
        hotspot_score = amendment_count / max(amendment_count) * 100,
        category = case_when(
          amendment_count >= quantile(amendment_count, 0.75) ~ "Muito Alto",
          amendment_count >= quantile(amendment_count, 0.5) ~ "Alto",
          amendment_count >= quantile(amendment_count, 0.25) ~ "Moderado",
          TRUE ~ "Baixo"
        )
      )

    return(hotspots)

  }, error = function(e) {
    warning("Error detecting hotspots: ", e$message)
    return(data.frame())
  })
}


#' Find Law by Reference String
#'
#' Helper to locate a law document from a reference string
#'
#' @param db_connection DBI connection
#' @param reference Reference string (e.g., "Lei nº 1234")
#' @return Data frame with matching documents
find_law_by_reference <- function(db_connection, reference) {

  if (is.na(reference) || reference == "") {
    return(data.frame())
  }

  # Clean reference
  ref_clean <- str_squish(reference)
  pattern <- sprintf("%%%s%%", ref_clean)

  result <- DBI::dbGetQuery(db_connection,
    "SELECT * FROM documents
     WHERE titulo ILIKE $1 OR urn ILIKE $1
     ORDER BY ano DESC
     LIMIT 1",
    list(pattern))

  return(result)
}


#' Analyze Amendment Cascades
#'
#' Detect cascading amendments where A amends B, B amends C, etc.
#'
#' @param db_connection DBI connection
#' @param min_chain_length Minimum cascade length to report
#' @return Data frame with cascade chains
#' @export
analyze_amendment_cascades <- function(db_connection, min_chain_length = 3) {

  if (is.null(db_connection)) {
    stop("Database connection required")
  }

  tryCatch({
    # Get all amendments
    amendments <- identify_amendments(db_connection)

    if (nrow(amendments) == 0) {
      return(data.frame())
    }

    # Build amendment graph
    edges <- amendments %>%
      filter(!is.na(referenced_laws)) %>%
      mutate(refs = str_split(referenced_laws, ";\\s*")) %>%
      unnest(refs) %>%
      select(from_id = id, from_title = titulo, from_year = ano,
             to_ref = refs)

    # Create igraph object
    g <- graph_from_data_frame(
      edges %>% select(from = from_id, to = to_ref),
      directed = TRUE
    )

    # Find all paths
    all_paths <- list()
    vertices <- V(g)

    for (i in 1:min(100, length(vertices))) {  # Limit for performance
      paths <- all_simple_paths(g, from = vertices[i], mode = "out")
      for (path in paths) {
        if (length(path) >= min_chain_length) {
          all_paths[[length(all_paths) + 1]] <- names(path)
        }
      }
    }

    if (length(all_paths) == 0) {
      return(data.frame())
    }

    # Convert to data frame
    cascades <- data.frame(
      cascade_id = seq_along(all_paths),
      chain_length = sapply(all_paths, length),
      chain = sapply(all_paths, paste, collapse = " → ")
    ) %>%
      arrange(desc(chain_length))

    # Add metadata
    cascades <- cascades %>%
      mutate(
        complexity_score = chain_length * 10,
        category = case_when(
          chain_length >= 5 ~ "Cascata Complexa",
          chain_length >= 4 ~ "Cascata Moderada",
          TRUE ~ "Cascata Simples"
        )
      )

    return(cascades)

  }, error = function(e) {
    warning("Error analyzing cascades: ", e$message)
    return(data.frame())
  })
}


#' Calculate Amendment Velocity
#'
#' Measure the rate of amendments over time
#'
#' @param db_connection DBI connection
#' @param window_years Rolling window for velocity calculation
#' @param by_jurisdiction Calculate separately by jurisdiction
#' @return Data frame with velocity metrics
#' @export
calculate_amendment_velocity <- function(db_connection,
                                        window_years = 3,
                                        by_jurisdiction = FALSE) {

  if (is.null(db_connection)) {
    stop("Database connection required")
  }

  tryCatch({
    # Get amendments
    amendments <- identify_amendments(db_connection)

    if (nrow(amendments) == 0) {
      return(data.frame())
    }

    # Calculate yearly counts
    if (by_jurisdiction) {
      yearly <- amendments %>%
        count(ano, nivel, name = "amendment_count") %>%
        arrange(nivel, ano)
    } else {
      yearly <- amendments %>%
        count(ano, name = "amendment_count") %>%
        arrange(ano)
    }

    # Calculate rolling average and velocity
    if (by_jurisdiction) {
      velocity <- yearly %>%
        group_by(nivel) %>%
        arrange(ano) %>%
        mutate(
          rolling_avg = zoo::rollapply(
            amendment_count, width = window_years,
            FUN = mean, align = "right", fill = NA, partial = TRUE
          ),
          velocity = amendment_count - lag(amendment_count),
          velocity_pct = round((velocity / lag(amendment_count)) * 100, 2),
          acceleration = velocity - lag(velocity)
        ) %>%
        ungroup()
    } else {
      velocity <- yearly %>%
        mutate(
          rolling_avg = zoo::rollapply(
            amendment_count, width = window_years,
            FUN = mean, align = "right", fill = NA, partial = TRUE
          ),
          velocity = amendment_count - lag(amendment_count),
          velocity_pct = round((velocity / lag(amendment_count)) * 100, 2),
          acceleration = velocity - lag(velocity)
        )
    }

    # Add trend classification
    velocity <- velocity %>%
      mutate(
        trend = case_when(
          is.na(velocity) ~ "Sem Dados",
          velocity > 0 & acceleration > 0 ~ "Aceleração Crescente",
          velocity > 0 & acceleration <= 0 ~ "Crescimento Desacelerando",
          velocity < 0 & acceleration < 0 ~ "Declínio Acelerando",
          velocity < 0 & acceleration >= 0 ~ "Declínio Desacelerando",
          TRUE ~ "Estável"
        )
      )

    return(velocity)

  }, error = function(e) {
    warning("Error calculating velocity: ", e$message)
    return(data.frame())
  })
}


#' Analyze Cross-Jurisdiction Amendment Patterns
#'
#' Track how amendments flow between Federal, State, and Municipal levels
#'
#' @param db_connection DBI connection
#' @param min_similarity Minimum text similarity to consider
#' @return Data frame with cross-jurisdiction patterns
#' @export
cross_jurisdiction_amendments <- function(db_connection, min_similarity = 0.3) {

  if (is.null(db_connection)) {
    stop("Database connection required")
  }

  tryCatch({
    # Get amendments by jurisdiction
    amendments <- identify_amendments(db_connection) %>%
      filter(!is.na(nivel))

    if (nrow(amendments) == 0) {
      return(data.frame())
    }

    # Count flows between jurisdictions
    flows <- amendments %>%
      group_by(nivel, ano) %>%
      summarise(
        amendment_count = n(),
        .groups = "drop"
      )

    # Identify temporal patterns
    patterns <- amendments %>%
      arrange(ano) %>%
      group_by(referenced_laws) %>%
      filter(n() > 1, !is.na(referenced_laws)) %>%
      summarise(
        jurisdictions = paste(unique(nivel), collapse = " → "),
        years = paste(sort(unique(ano)), collapse = " → "),
        count = n(),
        span_years = max(ano) - min(ano),
        .groups = "drop"
      ) %>%
      filter(str_detect(jurisdictions, "→"))  # Only cross-jurisdiction

    # Classify flow patterns
    patterns <- patterns %>%
      mutate(
        flow_type = case_when(
          str_detect(jurisdictions, "Federal.*Estadual") ~ "Federal → Estado",
          str_detect(jurisdictions, "Federal.*Municipal") ~ "Federal → Municipal",
          str_detect(jurisdictions, "Estadual.*Municipal") ~ "Estado → Municipal",
          str_detect(jurisdictions, "Estadual.*Federal") ~ "Estado → Federal",
          str_detect(jurisdictions, "Municipal.*Estadual") ~ "Municipal → Estado",
          str_detect(jurisdictions, "Municipal.*Federal") ~ "Municipal → Federal",
          TRUE ~ "Complexo"
        ),
        diffusion_speed = if_else(span_years > 0, count / span_years, 0)
      )

    return(list(
      flows_by_level = flows,
      cross_jurisdiction_patterns = patterns
    ))

  }, error = function(e) {
    warning("Error analyzing cross-jurisdiction patterns: ", e$message)
    return(list())
  })
}


#' Build Amendment Network Structure
#'
#' Create network representation of amendment relationships
#'
#' @param focal_doc Focal document
#' @param amendments_to Documents that amend focal
#' @param amendments_from Documents amended by focal
#' @return List with nodes and edges for network visualization
build_amendment_network <- function(focal_doc, amendments_to, amendments_from) {

  # Create nodes
  nodes <- data.frame(
    id = c(focal_doc$id,
           if(nrow(amendments_to) > 0) amendments_to$id else NULL,
           if(nrow(amendments_from) > 0) amendments_from$id else NULL),
    label = c(substr(focal_doc$titulo, 1, 50),
              if(nrow(amendments_to) > 0) substr(amendments_to$titulo, 1, 50) else NULL,
              if(nrow(amendments_from) > 0) substr(amendments_from$titulo, 1, 50) else NULL),
    type = c("focal",
             if(nrow(amendments_to) > 0) rep("amends_focal", nrow(amendments_to)) else NULL,
             if(nrow(amendments_from) > 0) rep("amended_by_focal", nrow(amendments_from)) else NULL),
    year = c(focal_doc$ano,
             if(nrow(amendments_to) > 0) amendments_to$ano else NULL,
             if(nrow(amendments_from) > 0) amendments_from$ano else NULL)
  ) %>%
    distinct()

  # Create edges
  edges <- data.frame()

  if (nrow(amendments_to) > 0) {
    edges <- bind_rows(edges, data.frame(
      from = amendments_to$id,
      to = focal_doc$id,
      type = "amends",
      year = amendments_to$ano
    ))
  }

  if (nrow(amendments_from) > 0) {
    edges <- bind_rows(edges, data.frame(
      from = focal_doc$id,
      to = amendments_from$id,
      type = "amends",
      year = focal_doc$ano
    ))
  }

  return(list(
    nodes = nodes,
    edges = edges
  ))
}


# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

cat("✅ Amendment Pattern Analysis Module loaded successfully\n")
cat("   Functions available:\n")
cat("   - identify_amendments()\n")
cat("   - build_amendment_timeline()\n")
cat("   - detect_amendment_hotspots()\n")
cat("   - analyze_amendment_cascades()\n")
cat("   - calculate_amendment_velocity()\n")
cat("   - cross_jurisdiction_amendments()\n")
