# Advanced Data Processing for Monitor Legislativo v4
# Data validation, enrichment, and quality assurance

library(dplyr)
library(stringr)
library(lubridate)
library(textcat)

#' Advanced data validation for legislative documents
#' @param data Raw legislative data
#' @return List with validation results and cleaned data
validate_legislative_documents <- function(data) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(list(
      valid_data = data.frame(),
      validation_report = list(
        total_records = 0,
        valid_records = 0,
        validation_rate = 0,
        errors = character(0)
      )
    ))
  }
  
  log_event(paste("Starting validation of", nrow(data), "documents"))
  
  validation_errors <- c()
  
  # Initialize validation flags
  data$validation_score <- 0
  data$validation_flags <- ""
  
  # 1. Title validation (required, minimum length)
  if ("titulo" %in% names(data)) {
    title_valid <- !is.na(data$titulo) & 
                   nchar(trimws(data$titulo)) >= 5 &
                   !str_detect(data$titulo, "^\\s*$")
    
    data$validation_score <- data$validation_score + ifelse(title_valid, 25, 0)
    data$validation_flags <- ifelse(
      !title_valid, 
      paste(data$validation_flags, "INVALID_TITLE", sep = ";"), 
      data$validation_flags
    )
    
    invalid_titles <- sum(!title_valid, na.rm = TRUE)
    if (invalid_titles > 0) {
      validation_errors <- c(validation_errors, 
                           paste("Invalid titles:", invalid_titles))
    }
  }
  
  # 2. Date validation
  if ("data" %in% names(data)) {
    # Try to parse dates
    data$data_parsed <- tryCatch({
      as.Date(data$data)
    }, error = function(e) {
      rep(NA, nrow(data))
    })
    
    # Validate date range (1988 Brazilian Constitution to future)
    min_date <- as.Date("1988-10-05")
    max_date <- Sys.Date() + 365
    
    date_valid <- !is.na(data$data_parsed) & 
                  data$data_parsed >= min_date & 
                  data$data_parsed <= max_date
    
    data$validation_score <- data$validation_score + ifelse(date_valid, 20, 0)
    data$validation_flags <- ifelse(
      !date_valid & !is.na(data$data),
      paste(data$validation_flags, "INVALID_DATE", sep = ";"),
      data$validation_flags
    )
    
    invalid_dates <- sum(!date_valid & !is.na(data$data), na.rm = TRUE)
    if (invalid_dates > 0) {
      validation_errors <- c(validation_errors,
                           paste("Invalid dates:", invalid_dates))
    }
  }
  
  # 3. Document type validation
  if ("tipo" %in% names(data)) {
    valid_types <- c("lei", "decreto", "portaria", "resolucao", "medida_provisoria",
                    "instrucao_normativa", "ordem_de_servico", "circular", "parecer")
    
    # Normalize types
    data$tipo_normalized <- str_to_lower(str_trim(data$tipo))
    data$tipo_normalized <- str_replace_all(data$tipo_normalized, "[^a-z_]", "_")
    
    type_valid <- data$tipo_normalized %in% valid_types
    
    data$validation_score <- data$validation_score + ifelse(type_valid, 15, 0)
    data$validation_flags <- ifelse(
      !type_valid & !is.na(data$tipo),
      paste(data$validation_flags, "INVALID_TYPE", sep = ";"),
      data$validation_flags
    )
    
    invalid_types <- sum(!type_valid & !is.na(data$tipo), na.rm = TRUE)
    if (invalid_types > 0) {
      validation_errors <- c(validation_errors,
                           paste("Invalid types:", invalid_types))
    }
  }
  
  # 4. Geographic validation
  if ("estado" %in% names(data)) {
    valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                     "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                     "RS", "RO", "RR", "SC", "SP", "SE", "TO")
    
    data$estado_normalized <- str_to_upper(str_trim(data$estado))
    state_valid <- data$estado_normalized %in% valid_states | is.na(data$estado)
    
    data$validation_score <- data$validation_score + ifelse(state_valid, 10, 0)
    data$validation_flags <- ifelse(
      !state_valid & !is.na(data$estado),
      paste(data$validation_flags, "INVALID_STATE", sep = ";"),
      data$validation_flags
    )
    
    invalid_states <- sum(!state_valid & !is.na(data$estado), na.rm = TRUE)
    if (invalid_states > 0) {
      validation_errors <- c(validation_errors,
                           paste("Invalid states:", invalid_states))
    }
  }
  
  # 5. Text quality validation
  if ("ementa" %in% names(data)) {
    ementa_quality <- !is.na(data$ementa) & 
                     nchar(trimws(data$ementa)) >= 20 &
                     !str_detect(data$ementa, "^[^a-zA-Z]*$")  # Not only numbers/symbols
    
    data$validation_score <- data$validation_score + ifelse(ementa_quality, 15, 0)
    data$validation_flags <- ifelse(
      !ementa_quality & !is.na(data$ementa),
      paste(data$validation_flags, "LOW_QUALITY_EMENTA", sep = ";"),
      data$validation_flags
    )
  }
  
  # 6. Source validation
  if ("fonte" %in% names(data)) {
    source_valid <- !is.na(data$fonte) & nchar(trimws(data$fonte)) > 0
    
    data$validation_score <- data$validation_score + ifelse(source_valid, 10, 0)
    data$validation_flags <- ifelse(
      !source_valid,
      paste(data$validation_flags, "MISSING_SOURCE", sep = ";"),
      data$validation_flags
    )
  }
  
  # 7. URL validation
  if ("url" %in% names(data)) {
    url_valid <- is.na(data$url) | 
                str_detect(data$url, "^https?://[^\\s]+\\.[^\\s]+")
    
    data$validation_score <- data$validation_score + ifelse(url_valid, 5, 0)
    data$validation_flags <- ifelse(
      !url_valid & !is.na(data$url),
      paste(data$validation_flags, "INVALID_URL", sep = ";"),
      data$validation_flags
    )
  }
  
  # Clean up validation flags
  data$validation_flags <- str_replace(data$validation_flags, "^;", "")
  data$validation_flags <- ifelse(data$validation_flags == "", NA, data$validation_flags)
  
  # Determine valid records (minimum 70% validation score)
  min_score <- 70
  valid_records <- data$validation_score >= min_score
  
  # Create validation report
  validation_report <- list(
    total_records = nrow(data),
    valid_records = sum(valid_records, na.rm = TRUE),
    validation_rate = round(sum(valid_records, na.rm = TRUE) / nrow(data) * 100, 2),
    average_score = round(mean(data$validation_score, na.rm = TRUE), 2),
    errors = validation_errors,
    score_distribution = table(cut(data$validation_score, 
                                  breaks = c(0, 30, 50, 70, 85, 100),
                                  labels = c("Poor", "Fair", "Good", "Very Good", "Excellent")))
  )
  
  # Filter valid data
  valid_data <- data[valid_records, ]
  
  log_event(paste("Validation completed:", validation_report$valid_records, "of", 
                 validation_report$total_records, "records valid"))
  
  return(list(
    valid_data = valid_data,
    all_data = data,
    validation_report = validation_report
  ))
}

#' Enhance legislative data with additional metadata
#' @param data Validated legislative data
#' @return Enhanced data with additional fields
enrich_legislative_data <- function(data) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(data)
  }
  
  log_event(paste("Enriching", nrow(data), "documents with metadata"))
  
  enhanced_data <- data %>%
    mutate(
      # Extract year from date
      ano = ifelse("data_parsed" %in% names(.), 
                  year(data_parsed), 
                  year(as.Date(data))),
      
      # Document age in days
      dias_desde_publicacao = as.numeric(Sys.Date() - as.Date(data)),
      
      # Text statistics
      titulo_palavras = ifelse(!is.na(titulo), str_count(titulo, "\\S+"), 0),
      ementa_palavras = ifelse(!is.na(ementa), str_count(ementa, "\\S+"), 0),
      
      # Document classification
      categoria = case_when(
        str_detect(str_to_lower(titulo), "transport|mobilidad|trânsit|ônibus|metrô") ~ "Transporte",
        str_detect(str_to_lower(titulo), "educação|escola|ensino|universidade") ~ "Educação",
        str_detect(str_to_lower(titulo), "saúde|hospital|sus|medicina") ~ "Saúde",
        str_detect(str_to_lower(titulo), "meio ambiente|ambiental|sustent|ecolog") ~ "Meio Ambiente",
        str_detect(str_to_lower(titulo), "econom|financ|orçament|fiscal") ~ "Economia",
        str_detect(str_to_lower(titulo), "segurança|polícia|crime|violência") ~ "Segurança",
        TRUE ~ "Outros"
      ),
      
      # Document complexity (basic heuristic)
      complexidade = case_when(
        ementa_palavras < 20 ~ "Baixa",
        ementa_palavras < 100 ~ "Média",
        ementa_palavras < 300 ~ "Alta",
        TRUE ~ "Muito Alta"
      ),
      
      # Regional classification
      regiao = case_when(
        estado_normalized %in% c("AC", "AP", "AM", "PA", "RO", "RR", "TO") ~ "Norte",
        estado_normalized %in% c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE") ~ "Nordeste",
        estado_normalized %in% c("DF", "GO", "MT", "MS") ~ "Centro-Oeste",
        estado_normalized %in% c("ES", "MG", "RJ", "SP") ~ "Sudeste",
        estado_normalized %in% c("PR", "RS", "SC") ~ "Sul",
        TRUE ~ "Não Classificado"
      ),
      
      # Document relevance score (for transport legislation)
      relevancia_transporte = case_when(
        str_detect(str_to_lower(paste(titulo, ementa)), 
                  "transport.*público|ônibus|metrô|trem|brt|vlt") ~ 100,
        str_detect(str_to_lower(paste(titulo, ementa)), 
                  "transport|mobilidad|trânsit") ~ 80,
        str_detect(str_to_lower(paste(titulo, ementa)), 
                  "via|rodoviá|ferroviá|portuá|aeroporto") ~ 60,
        str_detect(str_to_lower(paste(titulo, ementa)), 
                  "urbano|cidade|município") ~ 40,
        TRUE ~ 20
      )
    )
  
  # Language detection for quality control
  if (requireNamespace("textcat", quietly = TRUE)) {
    enhanced_data <- enhanced_data %>%
      mutate(
        idioma_detectado = sapply(titulo, function(x) {
          if (is.na(x) || nchar(x) < 10) return("unknown")
          tryCatch({
            textcat::textcat(x)
          }, error = function(e) "unknown")
        })
      )
  }
  
  log_event("Data enrichment completed")
  return(enhanced_data)
}

#' Detect and remove duplicate documents
#' @param data Legislative data
#' @param similarity_threshold Threshold for similarity (0-1)
#' @return Data with duplicates marked or removed
detect_duplicates <- function(data, similarity_threshold = 0.8) {
  
  if (is.null(data) || nrow(data) < 2) {
    return(data)
  }
  
  log_event(paste("Detecting duplicates in", nrow(data), "documents"))
  
  # Add duplicate flags
  data$is_duplicate <- FALSE
  data$duplicate_group <- NA
  data$similarity_score <- 0
  
  # Method 1: Exact matches
  exact_duplicates <- data %>%
    group_by(titulo, numero, data) %>%
    mutate(
      exact_duplicate_count = n(),
      exact_duplicate_id = row_number()
    ) %>%
    ungroup()
  
  # Mark exact duplicates (keep first occurrence)
  data$is_duplicate[exact_duplicates$exact_duplicate_count > 1 & 
                   exact_duplicates$exact_duplicate_id > 1] <- TRUE
  
  # Method 2: Title similarity for non-exact matches
  if (requireNamespace("utils", quietly = TRUE)) {
    non_exact <- data[!data$is_duplicate, ]
    
    if (nrow(non_exact) > 1) {
      for (i in 1:(nrow(non_exact) - 1)) {
        if (non_exact$is_duplicate[i]) next
        
        for (j in (i + 1):nrow(non_exact)) {
          if (non_exact$is_duplicate[j]) next
          
          # Calculate title similarity
          title1 <- str_to_lower(str_trim(non_exact$titulo[i]))
          title2 <- str_to_lower(str_trim(non_exact$titulo[j]))
          
          if (is.na(title1) || is.na(title2) || 
              nchar(title1) < 10 || nchar(title2) < 10) next
          
          # Simple similarity based on common words
          words1 <- unique(str_split(title1, "\\s+")[[1]])
          words2 <- unique(str_split(title2, "\\s+")[[1]])
          
          if (length(words1) == 0 || length(words2) == 0) next
          
          common_words <- length(intersect(words1, words2))
          total_words <- length(union(words1, words2))
          
          similarity <- common_words / total_words
          
          if (similarity >= similarity_threshold) {
            # Mark as potential duplicate
            non_exact$is_duplicate[j] <- TRUE
            non_exact$similarity_score[j] <- similarity
            non_exact$duplicate_group[j] <- i
          }
        }
      }
      
      # Update main data
      data[!data$is_duplicate, ] <- non_exact
    }
  }
  
  duplicates_found <- sum(data$is_duplicate, na.rm = TRUE)
  log_event(paste("Found", duplicates_found, "potential duplicates"))
  
  return(data)
}

#' Normalize and standardize document data
#' @param data Legislative data
#' @return Normalized data
normalize_document_data <- function(data) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(data)
  }
  
  log_event("Normalizing document data")
  
  normalized_data <- data %>%
    mutate(
      # Normalize text fields
      titulo = str_trim(str_squish(titulo)),
      ementa = str_trim(str_squish(ementa)),
      autor = str_trim(str_squish(autor)),
      
      # Standardize state codes
      estado = str_to_upper(str_trim(estado)),
      
      # Normalize document types
      tipo = case_when(
        str_detect(str_to_lower(tipo), "lei") ~ "Lei",
        str_detect(str_to_lower(tipo), "decreto") ~ "Decreto",
        str_detect(str_to_lower(tipo), "portaria") ~ "Portaria",
        str_detect(str_to_lower(tipo), "resolução|resolucao") ~ "Resolução",
        str_detect(str_to_lower(tipo), "medida.*provisória|medida.*provisoria") ~ "Medida Provisória",
        str_detect(str_to_lower(tipo), "instrução.*normativa|instrucao.*normativa") ~ "Instrução Normativa",
        TRUE ~ str_to_title(tipo)
      ),
      
      # Clean and validate URLs
      url = ifelse(
        !is.na(url) & str_detect(url, "^https?://"),
        str_trim(url),
        NA
      ),
      
      # Standardize source names
      fonte = case_when(
        str_detect(str_to_lower(fonte), "lexml") ~ "LexML Brasil",
        str_detect(str_to_lower(fonte), "camara|deputados") ~ "Câmara dos Deputados",
        str_detect(str_to_lower(fonte), "senado") ~ "Senado Federal",
        str_detect(str_to_lower(fonte), "assembleia") ~ "Assembleia Legislativa",
        str_detect(str_to_lower(fonte), "câmara.*municipal|camara.*municipal") ~ "Câmara Municipal",
        TRUE ~ str_to_title(fonte)
      ),
      
      # Clean numeric fields
      numero = str_trim(str_replace_all(numero, "[^0-9/.-]", "")),
      
      # Standardize dates
      data = as.Date(ifelse("data_parsed" %in% names(.), data_parsed, data))
    )
  
  log_event("Data normalization completed")
  return(normalized_data)
}

#' Create data quality report
#' @param data Legislative data with validation scores
#' @return Detailed quality report
create_quality_report <- function(data) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(list(message = "No data available for quality report"))
  }
  
  report <- list(
    overview = list(
      total_documents = nrow(data),
      date_range = if ("data" %in% names(data)) {
        paste(
          format(min(as.Date(data$data), na.rm = TRUE), "%d/%m/%Y"),
          "a",
          format(max(as.Date(data$data), na.rm = TRUE), "%d/%m/%Y")
        )
      } else "N/A"
    )
  )
  
  # Validation scores
  if ("validation_score" %in% names(data)) {
    report$quality_scores <- list(
      average_score = round(mean(data$validation_score, na.rm = TRUE), 2),
      median_score = round(median(data$validation_score, na.rm = TRUE), 2),
      high_quality = sum(data$validation_score >= 85, na.rm = TRUE),
      medium_quality = sum(data$validation_score >= 70 & data$validation_score < 85, na.rm = TRUE),
      low_quality = sum(data$validation_score < 70, na.rm = TRUE)
    )
  }
  
  # Completeness analysis
  completeness <- sapply(names(data), function(col) {
    round((sum(!is.na(data[[col]])) / nrow(data)) * 100, 1)
  })
  
  report$completeness <- as.list(completeness[order(-completeness)])
  
  # Geographic coverage
  if ("estado" %in% names(data)) {
    report$geographic_coverage <- list(
      states_covered = length(unique(data$estado[!is.na(data$estado)])),
      coverage_percentage = round(
        (length(unique(data$estado[!is.na(data$estado)])) / 27) * 100, 1
      ),
      top_states = head(sort(table(data$estado), decreasing = TRUE), 5)
    )
  }
  
  # Document types
  if ("tipo" %in% names(data)) {
    report$document_types <- list(
      unique_types = length(unique(data$tipo[!is.na(data$tipo)])),
      type_distribution = sort(table(data$tipo), decreasing = TRUE)
    )
  }
  
  # Temporal distribution
  if ("ano" %in% names(data)) {
    report$temporal_distribution <- list(
      year_range = paste(min(data$ano, na.rm = TRUE), "-", max(data$ano, na.rm = TRUE)),
      documents_per_year = sort(table(data$ano), decreasing = TRUE)
    )
  }
  
  # Data sources
  if ("fonte" %in% names(data)) {
    report$sources <- list(
      unique_sources = length(unique(data$fonte[!is.na(data$fonte)])),
      source_distribution = sort(table(data$fonte), decreasing = TRUE)
    )
  }
  
  # Duplicates
  if ("is_duplicate" %in% names(data)) {
    report$duplicates <- list(
      total_duplicates = sum(data$is_duplicate, na.rm = TRUE),
      duplicate_percentage = round(
        (sum(data$is_duplicate, na.rm = TRUE) / nrow(data)) * 100, 2
      )
    )
  }
  
  return(report)
}