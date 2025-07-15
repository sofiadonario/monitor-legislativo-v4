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
#' @param csv_path Path to the CSV file (optional, defaults to data/processed/lexml_latest_results.csv)
#' @return Data frame with LexML documents or NULL if failed
load_lexml_data <- function(csv_path = NULL) {
  tryCatch({
    # Default path if not provided
    if (is.null(csv_path)) {
      csv_path <- file.path("lexml_overview", "data", "processed", "lexml_latest_results.csv")
    }
    
    cat("📄 Loading enhanced LexML data from:", csv_path, "\n")
    
    # Check if file exists
    if (!file.exists(csv_path)) {
      warning(paste("LexML CSV file not found:", csv_path))
      return(NULL)
    }
    
    # Read CSV file with enhanced column types
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
        # Clean state codes
        estado = case_when(
          !is.na(state) & nchar(state) == 2 ~ toupper(state),
          TRUE ~ NA_character_
        ),
        # Parse enacting date with multiple formats
        data_publicacao = case_when(
          !is.na(enacting_date) & grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", enacting_date) ~ as.Date(enacting_date),
          !is.na(enacting_date) & grepl("^[0-9]{2}/[0-9]{2}/[0-9]{4}$", enacting_date) ~ as.Date(enacting_date, format = "%d/%m/%Y"),
          TRUE ~ NA_Date_
        ),
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
        # Add source identifier
        fonte = "LexML",
        # Add transport category based on search terms
        transport_category = case_when(
          grepl("combustível|energia|diesel|gasolina|etanol|GNV|hidrogênio", search_term, ignore.case = TRUE) ~ "combustiveis_energia",
          grepl("transporte|logística|carga|caminhão|navio|trem", search_term, ignore.case = TRUE) ~ "transporte_geral",
          grepl("tecnologia|inovacao|elétrico|autônomo", search_term, ignore.case = TRUE) ~ "tecnologia_inovacao",
          grepl("infraestrutura|rodovia|porto|ferrovia", search_term, ignore.case = TRUE) ~ "infraestrutura",
          grepl("regulamentação|norma|padrão", search_term, ignore.case = TRUE) ~ "regulamentacao_normas",
          grepl("incentivo|tributação|imposto|subsídio", search_term, ignore.case = TRUE) ~ "incentivos_tributacao",
          grepl("programa|política|governo", search_term, ignore.case = TRUE) ~ "programas_governamentais",
          grepl("máquina|equipamento|veículo", search_term, ignore.case = TRUE) ~ "maquinas_equipamentos",
          grepl("operação|serviço|manutenção", search_term, ignore.case = TRUE) ~ "operacoes_servicos",
          TRUE ~ "outros"
        ),
        # Add decade for temporal analysis
        decada = case_when(
          !is.na(data_publicacao) ~ paste0(substr(as.character(data_publicacao), 1, 3), "0s"),
          TRUE ~ NA_character_
        ),
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

#' Get LexML subject categories analysis
#' @return Data frame with subject categories
get_lexml_subject_categories <- function() {
  if (is.null(lexml_statistics)) {
    load_lexml_metadata()
  }
  
  if (!is.null(lexml_statistics) && !is.null(lexml_statistics$content_analysis) && 
      !is.null(lexml_statistics$content_analysis$subject_categories)) {
    
    categories <- lexml_statistics$content_analysis$subject_categories
    
    # Convert to data frame
    subject_data <- data.frame(
      category = names(categories),
      count = as.numeric(unlist(categories)),
      stringsAsFactors = FALSE
    ) %>%
      arrange(desc(count))
    
    return(subject_data)
  }
  
  return(NULL)
}

#' Get LexML regulatory agencies analysis
#' @return Vector of regulatory agencies
get_lexml_regulatory_agencies <- function() {
  if (is.null(lexml_statistics)) {
    load_lexml_metadata()
  }
  
  if (!is.null(lexml_statistics) && !is.null(lexml_statistics$content_analysis) && 
      !is.null(lexml_statistics$content_analysis$regulatory_agencies)) {
    return(lexml_statistics$content_analysis$regulatory_agencies)
  }
  
  return(NULL)
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

get_lexml_statistics <- function() {
  if (is.null(lexml_statistics)) {
    load_lexml_metadata()
  }
  return(lexml_statistics)
}

get_lexml_type_distribution <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (!is.null(lexml_data)) {
    return(lexml_data %>%
      count(urn_type, name = "count") %>%
      arrange(desc(count)))
  }
  
  return(NULL)
}

get_lexml_search_effectiveness <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (!is.null(lexml_data)) {
    return(lexml_data %>%
      group_by(search_term) %>%
      summarise(
        documents = n(),
        unique_types = n_distinct(urn_type),
        date_range = paste(min(data_publicacao, na.rm = TRUE), 
                          "-", 
                          max(data_publicacao, na.rm = TRUE))
      ) %>%
      arrange(desc(documents)))
  }
  
  return(NULL)
}