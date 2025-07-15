# LexML Data Loader Module
# Loads and integrates LexML metadata from CSV files

library(dplyr)
library(readr)
library(jsonlite)

# Global variables to store LexML data
lexml_data <- NULL
lexml_metadata <- NULL
lexml_statistics <- NULL

#' Load LexML data from CSV file
#' @param csv_path Path to the CSV file (optional, defaults to data/processed/lexml_latest_results.csv)
#' @return Data frame with LexML documents or NULL if failed
load_lexml_data <- function(csv_path = NULL) {
  tryCatch({
    # Default path if not provided
    if (is.null(csv_path)) {
      csv_path <- file.path("lexml_overview", "data", "processed", "lexml_latest_results.csv")
    }
    
    cat("📄 Loading LexML data from:", csv_path, "\n")
    
    # Check if file exists
    if (!file.exists(csv_path)) {
      warning(paste("LexML CSV file not found:", csv_path))
      return(NULL)
    }
    
    # Read CSV file
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
    
    # Process and clean data
    data <- data %>%
      mutate(
        # Clean state codes
        estado = case_when(
          !is.na(state) & nchar(state) == 2 ~ toupper(state),
          TRUE ~ NA_character_
        ),
        # Parse enacting date
        data_publicacao = case_when(
          !is.na(enacting_date) & grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", enacting_date) ~ as.Date(enacting_date),
          !is.na(enacting_date) & grepl("^[0-9]{2}/[0-9]{2}/[0-9]{4}$", enacting_date) ~ as.Date(enacting_date, format = "%d/%m/%Y"),
          TRUE ~ NA_Date_
        ),
        # Map document types
        tipo = case_when(
          urn_type == "legislation" ~ "lei",
          urn_type == "jurisprudence" ~ "jurisprudencia",
          urn_type == "doutrina" ~ "doutrina",
          TRUE ~ "outro"
        ),
        # Create ID if not present
        id = row_number(),
        # Rename title column
        titulo = title
      )
    
    cat("✅ Loaded", nrow(data), "LexML documents\n")
    
    # Store in global variable
    lexml_data <<- data
    
    return(data)
    
  }, error = function(e) {
    cat("❌ Error loading LexML data:", e$message, "\n")
    return(NULL)
  })
}

#' Load LexML metadata from JSON files
#' @return List with metadata and statistics or NULL if failed
load_lexml_metadata <- function() {
  tryCatch({
    # Load metadata JSON
    metadata_path <- file.path("lexml_overview", "data", "processed", "lexml_metadata.json")
    statistics_path <- file.path("lexml_overview", "data", "processed", "lexml_statistics.json")
    
    metadata <- NULL
    statistics <- NULL
    
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
    
    return(list(metadata = metadata, statistics = statistics))
    
  }, error = function(e) {
    cat("❌ Error loading LexML metadata:", e$message, "\n")
    return(NULL)
  })
}

#' Get combined documents from database and LexML
#' @param include_lexml Whether to include LexML data (default TRUE)
#' @param limit Maximum number of results
#' @return Data frame with combined documents
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

#' Get LexML statistics summary
#' @return List with statistics or NULL
get_lexml_statistics <- function() {
  if (is.null(lexml_statistics)) {
    load_lexml_metadata()
  }
  return(lexml_statistics)
}

#' Get document type distribution from LexML data
#' @return Data frame with type counts
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

#' Get search term effectiveness from LexML data
#' @return Data frame with search term statistics
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