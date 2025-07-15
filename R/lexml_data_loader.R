# LexML Data Loader Module
# Enhanced version with better database integration and comprehensive analytics
# Based on LexML Refinado v2.0 documentation

library(dplyr)
library(readr)
library(jsonlite)
library(plotly)
library(ggplot2)

# Global variables to store LexML data
lexml_data <- NULL
lexml_metadata <- NULL
lexml_statistics <- NULL
lexml_display_data <- NULL

#' Load LexML data from CSV file with enhanced processing
#' @param csv_path Path to the CSV file (optional, defaults to enhanced data)
#' @return Data frame with LexML documents or NULL if failed
load_lexml_data <- function(csv_path = NULL) {
  tryCatch({
    # Default path if not provided - try enhanced data first, fallback to original
    if (is.null(csv_path)) {
      enhanced_path <- file.path("lexml_overview", "data", "processed", "lexml_enhanced_results.csv")
      original_path <- file.path("lexml_overview", "data", "processed", "lexml_latest_results.csv")
      
      if (file.exists(enhanced_path)) {
        csv_path <- enhanced_path
        cat("📊 Using enhanced LexML dataset\n")
      } else if (file.exists(original_path)) {
        csv_path <- original_path
        cat("📊 Using original LexML dataset\n")
      } else {
        cat("❌ No LexML data file found\n")
        return(NULL)
      }
    }
    
    # Read CSV with proper column specifications
    data <- read_csv(csv_path,
                     col_types = cols(
                       search_term = col_character(),
                       date_searched = col_date(format = "%Y-%m-%d"),
                       url = col_character(),
                       title = col_character(),
                       urn = col_character(),
                       urn_type = col_character(),
                       country = col_character(),
                       state = col_character(),
                       municipality = col_character(),
                       justice = col_character(),
                       region = col_character(),
                       court_class = col_character(),
                       document_type_full = col_character(),
                       enacting_date = col_character(),
                       document_description = col_character(),
                       document_summary = col_character()
                     ),
                     locale = locale(encoding = "UTF-8"))
    
    # Enhanced data processing based on LexML Refinado v2.0
    data <- data %>%
      mutate(
        # Parse enacting date with multiple formats
        data_publicacao = as.Date(enacting_date, format = "%d/%m/%Y"),
        # Enhanced document type mapping
        tipo = case_when(
          urn_type == "legislation" ~ "lei",
          urn_type == "jurisprudence" ~ "jurisprudencia",
          urn_type == "doutrina" ~ "doutrina",
          TRUE ~ "outro"
        ),
        # Create ID if not present
        id = row_number(),
        # Rename title column
        titulo = title,
        # Add source identifier if not present
        fonte = ifelse("fonte" %in% colnames(data), fonte, "LexML"),
        # Add year for analysis
        ano = case_when(
          !is.na(data_publicacao) ~ as.numeric(format(data_publicacao, "%Y")),
          TRUE ~ NA_real_
        )
      )
    
    cat("✅ Enhanced LexML data loaded:", nrow(data), "documents\n")
    cat("📊 Document types:", paste(unique(data$tipo), collapse = ", "), "\n")
    cat("📊 Transport categories:", paste(unique(data$transport_category), collapse = ", "), "\n")
    
    # Store in global variable
    lexml_data <<- data
    
    return(data)
    
  }, error = function(e) {
    cat("❌ Error loading enhanced LexML data:", e$message, "\n")
    return(NULL)
  })
}

#' Load LexML metadata from JSON files with enhanced processing
#' @return List with metadata and statistics or NULL if failed
load_lexml_metadata <- function() {
  tryCatch({
    # Load metadata JSON files
    metadata_path <- file.path("lexml_overview", "data", "processed", "lexml_metadata.json")
    statistics_path <- file.path("lexml_overview", "data", "processed", "lexml_statistics.json")
    display_path <- file.path("lexml_overview", "data", "processed", "lexml_display_data.json")
    
    metadata <- NULL
    statistics <- NULL
    display_data <- NULL
    
    if (file.exists(metadata_path)) {
      metadata <- fromJSON(metadata_path)
      lexml_metadata <<- metadata
      cat("✅ Loaded LexML metadata\n")
    }
    
    if (file.exists(statistics_path)) {
      statistics <- fromJSON(statistics_path)
      lexml_statistics <<- statistics
      cat("✅ Loaded LexML statistics\n")
    }
    
    if (file.exists(display_path)) {
      display_data <- fromJSON(display_path)
      lexml_display_data <<- display_data
      cat("✅ Loaded LexML display data\n")
    }
    
    return(list(metadata = metadata, statistics = statistics, display_data = display_data))
    
  }, error = function(e) {
    cat("❌ Error loading LexML metadata:", e$message, "\n")
    return(NULL)
  })
}

#' Get LexML statistics for dashboard display
#' @return List with statistics or NULL if failed
get_lexml_statistics <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(NULL)
  }
  
  tryCatch({
    # Basic statistics
    total_docs <- nrow(lexml_data)
    unique_search_terms <- length(unique(lexml_data$search_term))
    date_range <- range(lexml_data$data_publicacao, na.rm = TRUE)
    
    # Document type distribution
    type_dist <- lexml_data %>%
      count(tipo, name = "count") %>%
      arrange(desc(count))
    
    # State distribution
    state_dist <- lexml_data %>%
      filter(!is.na(estado) & estado != "") %>%
      count(estado, name = "count") %>%
      arrange(desc(count))
    
    return(list(
      collection_info = list(
        total_documents = total_docs,
        unique_search_terms = unique_search_terms
      ),
      temporal_analysis = list(
        date_range = list(
          earliest = as.character(date_range[1]),
          latest = as.character(date_range[2])
        )
      ),
      document_distribution = list(
        by_type = setNames(type_dist$count, type_dist$tipo)
      ),
      state_distribution = list(
        by_state = setNames(state_dist$count, state_dist$estado)
      )
    ))
    
  }, error = function(e) {
    cat("❌ Error generating LexML statistics:", e$message, "\n")
    return(NULL)
  })
}

#' Get LexML type distribution
#' @return Data frame with type distribution
get_lexml_type_distribution <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(NULL)
  }
  
  tryCatch({
    lexml_data %>%
      count(tipo, name = "count") %>%
      arrange(desc(count))
  }, error = function(e) {
    cat("❌ Error getting LexML type distribution:", e$message, "\n")
    return(NULL)
  })
}

#' Get LexML search effectiveness
#' @return Data frame with search effectiveness
get_lexml_search_effectiveness <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(NULL)
  }
  
  tryCatch({
    lexml_data %>%
      group_by(search_term) %>%
      summarise(
        documents = n(),
        unique_types = n_distinct(tipo),
        .groups = "drop"
      ) %>%
      arrange(desc(documents)) %>%
      head(10)
  }, error = function(e) {
    cat("❌ Error getting LexML search effectiveness:", e$message, "\n")
    return(NULL)
  })
}

#' Get enhanced LexML analytics
#' @return List with comprehensive analytics
get_enhanced_lexml_analytics <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(NULL)
  }
  
  tryCatch({
    # Basic statistics
    total_docs <- nrow(lexml_data)
    unique_search_terms <- length(unique(lexml_data$search_term))
    date_range <- range(lexml_data$data_publicacao, na.rm = TRUE)
    
    # Document type distribution
    type_dist <- lexml_data %>%
      count(tipo, name = "count") %>%
      arrange(desc(count))
    
    # Transport category distribution
    category_dist <- lexml_data %>%
      count(transport_category, name = "count") %>%
      arrange(desc(count))
    
    # Temporal analysis by decade
    decade_dist <- lexml_data %>%
      filter(!is.na(decada)) %>%
      count(decada, name = "count") %>%
      arrange(decada)
    
    # Search term effectiveness
    search_effectiveness <- lexml_data %>%
      group_by(search_term) %>%
      summarise(
        documents = n(),
        unique_types = n_distinct(tipo),
        date_range = paste(min(data_publicacao, na.rm = TRUE), 
                          "-", 
                          max(data_publicacao, na.rm = TRUE))
      ) %>%
      arrange(desc(documents))
    
    # State distribution
    state_dist <- lexml_data %>%
      filter(!is.na(estado) & estado != "") %>%
      count(estado, name = "count") %>%
      arrange(desc(count))
    
    # Recent documents (last 30 days)
    recent_docs <- lexml_data %>%
      filter(!is.na(data_publicacao)) %>%
      filter(data_publicacao >= Sys.Date() - 30) %>%
      arrange(desc(data_publicacao))
    
    return(list(
      total_documents = total_docs,
      unique_search_terms = unique_search_terms,
      date_range = date_range,
      type_distribution = type_dist,
      category_distribution = category_dist,
      decade_distribution = decade_dist,
      search_effectiveness = search_effectiveness,
      state_distribution = state_dist,
      recent_documents = recent_docs
    ))
    
  }, error = function(e) {
    cat("❌ Error generating enhanced LexML analytics:", e$message, "\n")
    return(NULL)
  })
}

#' Get LexML quality metrics
#' @return List with quality metrics
get_lexml_quality_metrics <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(NULL)
  }
  
  tryCatch({
    # Calculate quality metrics based on LexML Refinado v2.0
    total_docs <- nrow(lexml_data)
    
    # Completeness (presence of required fields)
    completeness <- lexml_data %>%
      summarise(
        has_title = sum(!is.na(titulo) & titulo != "", na.rm = TRUE) / total_docs,
        has_urn = sum(!is.na(urn) & urn != "", na.rm = TRUE) / total_docs,
        has_date = sum(!is.na(data_publicacao), na.rm = TRUE) / total_docs,
        has_type = sum(!is.na(tipo) & tipo != "", na.rm = TRUE) / total_docs
      ) %>%
      mutate(overall_completeness = (has_title + has_urn + has_date + has_type) / 4)
    
    # Relevance (transport-related content)
    relevance <- lexml_data %>%
      summarise(
        transport_related = sum(grepl("transporte|carga|logística|combustível|energia", 
                                     paste(titulo, document_description, document_summary), 
                                     ignore.case = TRUE), na.rm = TRUE) / total_docs
      )
    
    # Consistency (data consistency checks)
    consistency <- lexml_data %>%
      summarise(
        valid_dates = sum(!is.na(data_publicacao) & data_publicacao > as.Date("1800-01-01") & 
                         data_publicacao <= Sys.Date(), na.rm = TRUE) / total_docs,
        valid_urns = sum(grepl("^urn:lex:", urn, ignore.case = TRUE), na.rm = TRUE) / total_docs
      )
    
    # Overall quality score
    quality_score <- (completeness$overall_completeness + relevance$transport_related + 
                     consistency$valid_dates + consistency$valid_urns) / 4
    
    # Quality grade
    quality_grade <- case_when(
      quality_score >= 0.9 ~ "A+",
      quality_score >= 0.8 ~ "A",
      quality_score >= 0.7 ~ "B",
      quality_score >= 0.6 ~ "C",
      quality_score >= 0.5 ~ "D",
      TRUE ~ "F"
    )
    
    return(list(
      completeness = completeness,
      relevance = relevance,
      consistency = consistency,
      quality_score = quality_score,
      quality_grade = quality_grade
    ))
    
  }, error = function(e) {
    cat("❌ Error calculating LexML quality metrics:", e$message, "\n")
    return(NULL)
  })
}

#' Get LexML subject categories
#' @return Data frame with subject categories
get_lexml_subject_categories <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(NULL)
  }
  
  tryCatch({
    lexml_data %>%
      count(transport_category, name = "count") %>%
      arrange(desc(count))
  }, error = function(e) {
    cat("❌ Error getting LexML subject categories:", e$message, "\n")
    return(NULL)
  })
}

#' Get LexML regulatory agencies
#' @return Data frame with regulatory agencies
get_lexml_regulatory_agencies <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(NULL)
  }
  
  tryCatch({
    # Extract agencies from URNs and titles
    agencies_data <- lexml_data %>%
      mutate(
        agency = case_when(
          grepl("agencia.nacional", urn, ignore.case = TRUE) ~ "ANTAQ",
          grepl("agencia.nacional.energia", urn, ignore.case = TRUE) ~ "ANEEL",
          grepl("agencia.nacional.petroleo", urn, ignore.case = TRUE) ~ "ANP",
          grepl("ministerio.transportes", urn, ignore.case = TRUE) ~ "Ministério dos Transportes",
          grepl("ministerio.minas.energia", urn, ignore.case = TRUE) ~ "Ministério de Minas e Energia",
          TRUE ~ "Outros"
        )
      ) %>%
      count(agency, name = "documents") %>%
      arrange(desc(documents))
    
    return(agencies_data)
    
  }, error = function(e) {
    cat("❌ Error getting LexML regulatory agencies:", e$message, "\n")
    return(NULL)
  })
}

# Keep existing functions for backward compatibility
get_combined_documents <- function(include_lexml = TRUE, limit = NULL) {
  # Get database documents if available
  db_docs <- NULL
  if (exists("get_documents", mode = "function")) {
    db_docs <- get_documents(limit = limit)
  }
  
  # Get LexML documents if requested
  lexml_docs <- NULL
  if (include_lexml) {
    if (is.null(lexml_data)) {
      load_lexml_data()
    }
    lexml_docs <- lexml_data
  }
  
  # Combine results
  if (!is.null(db_docs) && !is.null(lexml_docs)) {
    # Select common columns
    common_cols <- c("id", "titulo", "tipo", "estado", "data_publicacao", "url", "urn")
    
    db_docs_subset <- db_docs %>% 
      select(any_of(common_cols)) %>%
      mutate(source = "database")
    
    lexml_docs_subset <- lexml_docs %>%
      select(any_of(common_cols)) %>%
      mutate(source = "lexml")
    
    # Combine and remove duplicates based on URN
    combined <- bind_rows(db_docs_subset, lexml_docs_subset) %>%
      distinct(urn, .keep_all = TRUE)
    
    if (!is.null(limit)) {
      combined <- head(combined, limit)
    }
    
    return(combined)
    
  } else if (!is.null(db_docs)) {
    return(db_docs)
  } else if (!is.null(lexml_docs)) {
    # Format LexML data to match expected structure
    result <- lexml_docs %>%
      select(id, titulo, tipo, estado, data_publicacao, url, urn,
             search_term, document_type_full, document_description, document_summary) %>%
      mutate(source = "lexml")
    
    if (!is.null(limit)) {
      result <- head(result, limit)
    }
    
    return(result)
  }
  
  return(NULL)
} 