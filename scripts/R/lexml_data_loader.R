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

#' Load LexML data from PostgreSQL database with enhanced processing
#' @param use_csv Force use CSV fallback (optional, defaults to FALSE)
#' @return Data frame with LexML documents or NULL if failed
load_lexml_data <- function(use_csv = FALSE) {
  tryCatch({
    # First, try to load from PostgreSQL database
    if (!use_csv && exists("get_documents") && exists("db_pool") && !is.null(db_pool)) {
      cat("🔄 Loading LexML data from PostgreSQL database...\n")
      
      # Get documents from database
      lexml_data <- get_documents()
      
      if (!is.null(lexml_data) && nrow(lexml_data) > 0) {
        cat("✅ Enhanced LexML data loaded from database:", nrow(lexml_data), "documents\n")
        cat("📊 Document types:", paste(unique(lexml_data$tipo), collapse = ", "), "\n")
        
        # Transform to expected format for compatibility
        lexml_processed <- lexml_data %>%
          mutate(
            State = estado,
            Municipality = ifelse(is.na(municipio) | municipio == "", "", municipio),
            Title = titulo,
            Enacting_date = enacting_date,
            Urn_type = tipo,
            Document_summary = ifelse(is.null(conteudo), "", as.character(conteudo)),
            Document_description = ifelse(is.null(document_type_full), "", as.character(document_type_full)),
            Search_term = ifelse(is.null(search_term), "", as.character(search_term)),
            Urn = ifelse(is.null(urn), "", as.character(urn)),
            Url = ifelse(is.null(url), "", as.character(url)),
            Country = "br",
            Justice = "",
            Region = "",
            Court_class = "",
            Document_type_full = ifelse(is.null(document_type_full), "", as.character(document_type_full))
          )
        
        return(lexml_processed)
      } else {
        cat("⚠️ No data returned from database, falling back to CSV\n")
      }
    }
    
    # Fallback to CSV if database unavailable
    if (use_csv || !exists("db_pool") || is.null(db_pool)) {
      cat("🔄 Loading LexML data from CSV fallback...\n")
      cat("DEBUG: Current working directory:", getwd(), "\n")
      
      # Try multiple path variations to handle different deployment environments
      possible_paths <- c(
        file.path("data_current", "processed", "Geral.csv"),
        file.path(".", "data_current", "processed", "Geral.csv"),
        file.path("..", "data_current", "processed", "Geral.csv"),
        file.path("data_current", "raw", "Geral.csv"),
        file.path(".", "data_current", "raw", "Geral.csv"),
        file.path("..", "data_current", "raw", "Geral.csv"),
        file.path("lexml_overview", "use_version", "Geral.csv"),
        file.path(".", "lexml_overview", "use_version", "Geral.csv"),
        file.path("..", "lexml_overview", "use_version", "Geral.csv"),
        "Geral.csv",
        file.path("use_version", "Geral.csv")
      )
      
      use_version_path <- NULL
      for (path in possible_paths) {
        cat("DEBUG: Checking path:", path, "- exists:", file.exists(path), "\n")
        if (file.exists(path)) {
          use_version_path <- path
          break
        }
      }
      
      # Fallback paths
      enhanced_path <- file.path("data_current", "processed", "lexml_enhanced_results.csv")
      original_path <- file.path("data_current", "processed", "lexml_latest_results.csv")
      
      if (!is.null(use_version_path)) {
        csv_path <- use_version_path
        cat("📊 Using LexML dataset from use_version (1957 documents) at:", csv_path, "\n")
      } else if (file.exists(enhanced_path)) {
        csv_path <- enhanced_path
        cat("📊 Using enhanced LexML dataset\n")
      } else if (file.exists(original_path)) {
        csv_path <- original_path
        cat("📊 Using original LexML dataset\n")
      } else {
        cat("❌ No LexML data file found\n")
        cat("DEBUG: Files in current directory:\n")
        files <- list.files(".", recursive = TRUE, pattern = "*.csv")
        cat("DEBUG: CSV files found:", paste(files, collapse = ", "), "\n")
        return(NULL)
      }
    }
    
    # Read CSV with proper column specifications (case-sensitive column names)
    data <- read_csv(csv_path,
                     col_types = cols(
                       Search_term = col_character(),
                       Date_searched = col_date(format = "%Y-%m-%d"),
                       Url = col_character(),
                       Title = col_character(),
                       Urn = col_character(),
                       Urn_type = col_character(),
                       Country = col_character(),
                       State = col_character(),
                       Municipality = col_character(),
                       Justice = col_character(),
                       Region = col_character(),
                       Court_class = col_character(),
                       Document_type_full = col_character(),
                       Enacting_date = col_datetime(format = "%Y-%m-%d %H:%M:%S"),
                       Document_description = col_character(),
                       Document_summary = col_character()
                     ),
                     locale = locale(encoding = "UTF-8"))
    
    # Enhanced data processing based on LexML Refinado v2.0
    data <- data %>%
      mutate(
        # Convert column names to lowercase for consistency
        search_term = Search_term,
        date_searched = Date_searched,
        url = Url,
        title = Title,
        urn = Urn,
        urn_type = Urn_type,
        country = Country,
        state = State,
        municipality = Municipality,
        justice = Justice,
        region = Region,
        court_class = Court_class,
        document_type_full = Document_type_full,
        enacting_date = Enacting_date,
        document_description = Document_description,
        document_summary = Document_summary,
        # Parse enacting date 
        data_publicacao = as.Date(Enacting_date),
        # Enhanced document type mapping
        tipo = case_when(
          Urn_type == "legislation" ~ "lei",
          Urn_type == "jurisprudence" ~ "jurisprudencia",
          Urn_type == "doutrina" ~ "doutrina",
          TRUE ~ "outro"
        ),
        # Create ID if not present
        id = row_number(),
        # Set title column
        titulo = Title,
        # Set state column
        estado = State,
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
    metadata_path <- file.path("data_current", "processed", "lexml_metadata.json")
    statistics_path <- file.path("data_current", "processed", "lexml_statistics.json")
    display_path <- file.path("data_current", "processed", "lexml_display_data.json")
    
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

#' Load specific LexML data file for different categories and transport modes
#' @param category Category of documents ("legislation", "jurisprudence", "doctrine", "outros")
#' @param transport_mode Transport mode ("geral", "aéreo", "rodoviário", "marítimo")
#' @return Data frame with LexML documents or NULL if failed
load_specific_lexml_data <- function(category = "legislation", transport_mode = "geral") {
  tryCatch({
    # Map category to file name
    category_mapping <- list(
      "legislation" = "Legislação",
      "jurisprudence" = "Jurisprudência", 
      "doctrine" = "Doutrina",
      "outros" = "Outros"
    )
    
    # Map transport mode to file suffix
    mode_mapping <- list(
      "geral" = "Geral",
      "aéreo" = "Aéreo",
      "rodoviário" = "Rodoviário", 
      "marítimo" = "Marítimo"
    )
    
    if (!category %in% names(category_mapping)) {
      cat("❌ Invalid category:", category, "\n")
      return(NULL)
    }
    
    if (!transport_mode %in% names(mode_mapping)) {
      cat("❌ Invalid transport mode:", transport_mode, "\n")
      return(NULL)
    }
    
    # Construct file name
    file_name <- paste0(category_mapping[[category]], "___", mode_mapping[[transport_mode]], ".csv")
    
    # Try multiple path variations
    possible_paths <- c(
      file.path("data_current", "processed", file_name),
      file.path(".", "data_current", "processed", file_name),
      file.path("..", "data_current", "processed", file_name),
      file.path("data_current", "raw", file_name),
      file.path(".", "data_current", "raw", file_name),
      file.path("..", "data_current", "raw", file_name)
    )
    
    csv_path <- NULL
    for (path in possible_paths) {
      cat("DEBUG: Checking path:", path, "- exists:", file.exists(path), "\n")
      if (file.exists(path)) {
        csv_path <- path
        break
      }
    }
    
    if (is.null(csv_path)) {
      cat("❌ File not found:", file_name, "\n")
      return(NULL)
    }
    
    cat("📊 Loading specific LexML data:", file_name, "from:", csv_path, "\n")
    
    # Read CSV with proper column specifications
    data <- read_csv(csv_path,
                     col_types = cols(
                       Search_term = col_character(),
                       Date_searched = col_date(format = "%Y-%m-%d"),
                       Url = col_character(),
                       Title = col_character(),
                       Urn = col_character(),
                       Urn_type = col_character(),
                       Country = col_character(),
                       State = col_character(),
                       Municipality = col_character(),
                       Justice = col_character(),
                       Region = col_character(),
                       Court_class = col_character(),
                       Document_type_full = col_character(),
                       Enacting_date = col_datetime(format = "%Y-%m-%d %H:%M:%S"),
                       Document_description = col_character(),
                       Document_summary = col_character()
                     ),
                     locale = locale(encoding = "UTF-8"))
    
    # Enhanced data processing
    data <- data %>%
      mutate(
        # Convert column names to lowercase for consistency
        search_term = Search_term,
        date_searched = Date_searched,
        url = Url,
        title = Title,
        urn = Urn,
        urn_type = Urn_type,
        country = Country,
        state = State,
        municipality = Municipality,
        justice = Justice,
        region = Region,
        court_class = Court_class,
        document_type_full = Document_type_full,
        enacting_date = Enacting_date,
        document_description = Document_description,
        document_summary = Document_summary,
        # Parse enacting date 
        data_publicacao = as.Date(Enacting_date),
        # Enhanced document type mapping
        tipo = case_when(
          Urn_type == "legislation" ~ "lei",
          Urn_type == "jurisprudence" ~ "jurisprudencia",
          Urn_type == "doutrina" ~ "doutrina",
          TRUE ~ "outro"
        ),
        # Create ID if not present
        id = row_number(),
        # Set title column
        titulo = Title,
        # Set state column
        estado = State,
        # Add source identifier
        fonte = "LexML",
        # Add category and transport mode for filtering
        category = category,
        transport_mode = transport_mode,
        # Add year for analysis
        ano = case_when(
          !is.na(data_publicacao) ~ as.numeric(format(data_publicacao, "%Y")),
          TRUE ~ NA_real_
        )
      )
    
    cat("✅ Specific LexML data loaded:", nrow(data), "documents from", file_name, "\n")
    
    return(data)
    
  }, error = function(e) {
    cat("❌ Error loading specific LexML data:", e$message, "\n")
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

#' Get search analytics from LexML data
#' @return List with analytics data
get_lexml_search_analytics <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_day = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      documents_by_species = data.frame(),
      documents_by_gender_species = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  }
  
  cat("DEBUG: get_lexml_search_analytics() called\n")
  
  tryCatch({
    # Total documents
    total <- nrow(lexml_data)
    cat("DEBUG: Total documents found:", total, "\n")
    
    # Documents by year
    by_year <- lexml_data %>%
      filter(!is.na(data_publicacao)) %>%
      mutate(year = as.numeric(format(data_publicacao, "%Y"))) %>%
      count(year, name = "count") %>%
      arrange(desc(year)) %>%
      head(10)
    cat("DEBUG: Year query got", nrow(by_year), "rows\n")
    
    # Documents by month
    current_year <- as.numeric(format(Sys.Date(), "%Y"))
    by_month <- lexml_data %>%
      filter(!is.na(data_publicacao)) %>%
      filter(format(data_publicacao, "%Y") == as.character(current_year)) %>%
      mutate(month = as.numeric(format(data_publicacao, "%m"))) %>%
      count(month, name = "count") %>%
      arrange(month)
    cat("DEBUG: Month query got", nrow(by_month), "rows\n")
    
    # Documents by day (last 30 days)
    by_day <- lexml_data %>%
      filter(!is.na(data_publicacao)) %>%
      filter(data_publicacao >= Sys.Date() - 30) %>%
      mutate(day = format(data_publicacao, "%Y-%m-%d")) %>%
      count(day, name = "count") %>%
      arrange(day)
    cat("DEBUG: Day query got", nrow(by_day), "rows\n")
    
    # Documents by state
    by_state <- lexml_data %>%
      filter(!is.na(estado) & estado != "") %>%
      count(estado, name = "count") %>%
      arrange(desc(count)) %>%
      head(10)
    names(by_state) <- c("state", "count")
    cat("DEBUG: State query got", nrow(by_state), "rows\n")
    
    # Documents by type
    by_type <- lexml_data %>%
      count(tipo, name = "count") %>%
      arrange(desc(count))
    names(by_type) <- c("type", "count")
    cat("DEBUG: Type query got", nrow(by_type), "rows\n")
    
    # Documents by species (empty for now)
    by_species <- data.frame(species = character(), count = numeric())
    cat("DEBUG: Species query got", nrow(by_species), "rows\n")
    
    # Gender species (empty for now)
    by_gender_species <- data.frame(month = numeric(), gender_ratio = numeric())
    cat("DEBUG: Gender-Species query got", nrow(by_gender_species), "rows\n")
    
    # Recent documents
    recent <- lexml_data %>%
      arrange(desc(data_publicacao)) %>%
      head(10) %>%
      select(id, titulo, tipo, estado, data_publicacao, url)
    cat("DEBUG: Recent query got", nrow(recent), "rows\n")
    
    # Date range
    date_range <- range(lexml_data$data_publicacao, na.rm = TRUE)
    cat("DEBUG: Date range query completed\n")
    
    cat("DEBUG: Analytics completed successfully\n")
    
    return(list(
      total_documents = total,
      documents_by_year = by_year,
      documents_by_month = by_month,
      documents_by_day = by_day,
      documents_by_state = by_state,
      documents_by_type = by_type,
      documents_by_species = by_species,
      documents_by_gender_species = by_gender_species,
      recent_documents = recent,
      date_range = list(
        min = as.character(date_range[1]),
        max = as.character(date_range[2])
      )
    ))
    
  }, error = function(e) {
    cat("ERROR in get_lexml_search_analytics:", e$message, "\n")
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_day = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      documents_by_species = data.frame(),
      documents_by_gender_species = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  })
}

#' Get unique document types from LexML data
#' @return Character vector of document types
get_lexml_document_types <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(character())
  }
  
  tryCatch({
    types <- unique(lexml_data$tipo)
    types <- types[!is.na(types) & types != ""]
    cat("DEBUG: Found document types:", paste(types, collapse = ", "), "\n")
    return(sort(types))
  }, error = function(e) {
    cat("ERROR in get_lexml_document_types:", e$message, "\n")
    return(character())
  })
}

#' Get unique states from LexML data
#' @return Character vector of states
get_lexml_states <- function() {
  if (is.null(lexml_data)) {
    load_lexml_data()
  }
  
  if (is.null(lexml_data)) {
    return(character())
  }
  
  tryCatch({
    states <- unique(lexml_data$estado)
    states <- states[!is.na(states) & states != ""]
    cat("DEBUG: Found states:", paste(states, collapse = ", "), "\n")
    return(sort(states))
  }, error = function(e) {
    cat("ERROR in get_lexml_states:", e$message, "\n")
    return(character())
  })
} 

#' Load specific LexML data file for different categories and transport modes
#' @param category Category of documents ("legislation", "jurisprudence", "doctrine", "outros")
#' @param transport_mode Transport mode ("geral", "aéreo", "rodoviário", "marítimo")
#' @return Data frame with LexML documents or NULL if failed
load_specific_lexml_data <- function(category = "legislation", transport_mode = "geral") {
  tryCatch({
    # Map category to file name
    category_mapping <- list(
      "legislation" = "Legislação",
      "jurisprudence" = "Jurisprudência", 
      "doctrine" = "Doutrina",
      "outros" = "Outros"
    )
    
    # Map transport mode to file suffix
    mode_mapping <- list(
      "geral" = "Geral",
      "aéreo" = "Aéreo",
      "rodoviário" = "Rodoviário", 
      "marítimo" = "Marítimo"
    )
    
    if (!category %in% names(category_mapping)) {
      cat("❌ Invalid category:", category, "\n")
      return(NULL)
    }
    
    if (!transport_mode %in% names(mode_mapping)) {
      cat("❌ Invalid transport mode:", transport_mode, "\n")
      return(NULL)
    }
    
    # Construct file name
    file_name <- paste0(category_mapping[[category]], "___", mode_mapping[[transport_mode]], ".csv")
    
    # Try multiple path variations
    possible_paths <- c(
      file.path("data_current", "processed", file_name),
      file.path(".", "data_current", "processed", file_name),
      file.path("..", "data_current", "processed", file_name),
      file.path("data_current", "raw", file_name),
      file.path(".", "data_current", "raw", file_name),
      file.path("..", "data_current", "raw", file_name)
    )
    
    csv_path <- NULL
    for (path in possible_paths) {
      cat("DEBUG: Checking path:", path, "- exists:", file.exists(path), "\n")
      if (file.exists(path)) {
        csv_path <- path
        break
      }
    }
    
    if (is.null(csv_path)) {
      cat("❌ File not found:", file_name, "\n")
      return(NULL)
    }
    
    cat("📊 Loading specific LexML data:", file_name, "from:", csv_path, "\n")
    
    # Read CSV with proper column specifications
    data <- read_csv(csv_path,
                     col_types = cols(
                       Search_term = col_character(),
                       Date_searched = col_date(format = "%Y-%m-%d"),
                       Url = col_character(),
                       Title = col_character(),
                       Urn = col_character(),
                       Urn_type = col_character(),
                       Country = col_character(),
                       State = col_character(),
                       Municipality = col_character(),
                       Justice = col_character(),
                       Region = col_character(),
                       Court_class = col_character(),
                       Document_type_full = col_character(),
                       Enacting_date = col_datetime(format = "%Y-%m-%d %H:%M:%S"),
                       Document_description = col_character(),
                       Document_summary = col_character()
                     ),
                     locale = locale(encoding = "UTF-8"))
    
    # Enhanced data processing
    data <- data %>%
      mutate(
        # Convert column names to lowercase for consistency
        search_term = Search_term,
        date_searched = Date_searched,
        url = Url,
        title = Title,
        urn = Urn,
        urn_type = Urn_type,
        country = Country,
        state = State,
        municipality = Municipality,
        justice = Justice,
        region = Region,
        court_class = Court_class,
        document_type_full = Document_type_full,
        enacting_date = Enacting_date,
        document_description = Document_description,
        document_summary = Document_summary,
        # Parse enacting date 
        data_publicacao = as.Date(Enacting_date),
        # Enhanced document type mapping
        tipo = case_when(
          Urn_type == "legislation" ~ "lei",
          Urn_type == "jurisprudence" ~ "jurisprudencia",
          Urn_type == "doutrina" ~ "doutrina",
          TRUE ~ "outro"
        ),
        # Create ID if not present
        id = row_number(),
        # Set title column
        titulo = Title,
        # Set state column
        estado = State,
        # Add source identifier
        fonte = "LexML",
        # Add category and transport mode for filtering
        category = category,
        transport_mode = transport_mode,
        # Add year for analysis
        ano = case_when(
          !is.na(data_publicacao) ~ as.numeric(format(data_publicacao, "%Y")),
          TRUE ~ NA_real_
        )
      )
    
    cat("✅ Specific LexML data loaded:", nrow(data), "documents from", file_name, "\n")
    
    return(data)
    
  }, error = function(e) {
    cat("❌ Error loading specific LexML data:", e$message, "\n")
    return(NULL)
  })
}