# Data Processing and Validation Module
# Standardizes data from different Brazilian government APIs

library(dplyr)
library(stringr)
library(lubridate)
library(textclean)
library(futile.logger)

#' Standardize legislative data from different sources
#' @param data Raw data from API
#' @param source_name Name of the data source
#' @return Standardized data frame
standardize_legislative_data <- function(data, source_name = NULL) {
  
  if (is.null(data) || !is.data.frame(data) || nrow(data) == 0) {
    return(NULL)
  }
  
  flog.info("Standardizing %d records from source: %s", nrow(data), source_name %||% "unknown")
  
  # Create standardized column mapping
  standardized <- data %>%
    # Add source tracking
    mutate(
      fonte_original = source_name %||% fonte %||% "Não identificado",
      data_processamento = Sys.time()
    ) %>%
    # Standardize common columns with multiple possible names
    mutate(
      # Title standardization
      titulo = case_when(
        !is.na(titulo) ~ titulo,
        !is.na(ementa) ~ ementa,
        !is.na(descricao) ~ descricao,
        !is.na(nome) ~ nome,
        !is.na(title) ~ title,
        !is.na(subject) ~ subject,
        TRUE ~ "Título não disponível"
      ),
      
      # Document type standardization
      tipo = case_when(
        !is.na(tipo) ~ tolower(tipo),
        !is.na(tipo_proposicao) ~ tolower(tipo_proposicao),
        !is.na(type) ~ tolower(type),
        !is.na(category) ~ tolower(category),
        str_detect(tolower(titulo), "\\blei\\b") ~ "lei",
        str_detect(tolower(titulo), "\\bdecreto\\b") ~ "decreto",
        str_detect(tolower(titulo), "\\bportaria\\b") ~ "portaria",
        str_detect(tolower(titulo), "\\bresolução\\b") ~ "resolucao",
        str_detect(tolower(titulo), "\\bmedida provisória\\b") ~ "medida_provisoria",
        TRUE ~ "outros"
      ),
      
      # Number standardization
      numero = case_when(
        !is.na(numero) ~ as.character(numero),
        !is.na(number) ~ as.character(number),
        !is.na(codigo) ~ as.character(codigo),
        !is.na(id) ~ as.character(id),
        TRUE ~ extract_number_from_title(titulo)
      ),
      
      # Date standardization
      data = standardize_date_column(data, dataApresentacao, data_apresentacao, 
                                   date, created_date, data_criacao),
      
      # Year extraction
      ano = year(data),
      
      # Summary/description standardization
      resumo = case_when(
        !is.na(resumo) ~ resumo,
        !is.na(ementa) ~ ementa,
        !is.na(explicacao) ~ explicacao,
        !is.na(summary) ~ summary,
        !is.na(description) ~ description,
        TRUE ~ str_trunc(titulo, 200)
      ),
      
      # Author standardization
      autor = case_when(
        !is.na(autor) ~ autor,
        !is.na(nomeAutor) ~ nomeAutor,
        !is.na(author) ~ author,
        !is.na(proponente) ~ proponente,
        TRUE ~ "Não identificado"
      ),
      
      # Status standardization
      status = case_when(
        !is.na(status) ~ status,
        !is.na(situacao) ~ situacao,
        !is.na(estado) ~ estado,
        !is.na(fase) ~ fase,
        TRUE ~ "Em tramitação"
      ),
      
      # Geographic standardization
      estado = case_when(
        !is.na(estado) ~ toupper(estado),
        !is.na(uf) ~ toupper(uf),
        !is.na(state) ~ toupper(state),
        str_detect(fonte_original, "Câmara|Senado|Federal") ~ "DF",
        TRUE ~ extract_state_from_authority()
      ),
      
      municipio = case_when(
        !is.na(municipio) ~ municipio,
        !is.na(cidade) ~ cidade,
        !is.na(municipality) ~ municipality,
        !is.na(city) ~ city,
        TRUE ~ extract_municipality_from_authority()
      ),
      
      # URL standardization
      url = case_when(
        !is.na(url) ~ url,
        !is.na(link) ~ link,
        !is.na(uri) ~ uri,
        !is.na(urlInteiroTeor) ~ urlInteiroTeor,
        TRUE ~ build_document_url()
      )
    ) %>%
    # Clean text fields
    mutate(
      titulo = clean_text(titulo),
      resumo = clean_text(resumo),
      autor = clean_text(autor)
    ) %>%
    # Add computed fields
    mutate(
      # Create unique identifier
      id_unico = create_unique_id(titulo, numero, data, fonte_original),
      
      # Classification
      nivel_governo = case_when(
        estado == "DF" & str_detect(fonte_original, "Câmara|Senado") ~ "Federal",
        !is.na(municipio) ~ "Municipal",
        !is.na(estado) ~ "Estadual",
        TRUE ~ "Federal"
      ),
      
      # Academic citation
      citacao = create_academic_citation(titulo, tipo, numero, data, autor, fonte_original),
      
      # Keywords extraction
      palavras_chave = extract_keywords(titulo, resumo),
      
      # Time since publication
      dias_desde_publicacao = as.numeric(Sys.Date() - as.Date(data))
    ) %>%
    # Select final standardized columns
    select(
      id_unico,
      titulo,
      tipo,
      numero,
      data,
      ano,
      resumo,
      autor,
      status,
      estado,
      municipio,
      nivel_governo,
      fonte_original,
      url,
      citacao,
      palavras_chave,
      dias_desde_publicacao,
      data_processamento
    ) %>%
    # Remove invalid records
    filter(
      !is.na(titulo),
      !is.na(data),
      nchar(titulo) > 5,
      data >= as.Date("1988-01-01"),  # After current constitution
      data <= Sys.Date()
    ) %>%
    # Ensure data quality
    distinct(id_unico, .keep_all = TRUE)
  
  flog.info("Standardization complete. Final records: %d", nrow(standardized))
  
  return(standardized)
}

#' Standardize date columns from multiple possible formats
standardize_date_column <- function(...) {
  date_cols <- list(...)
  
  for (col in date_cols) {
    if (!is.null(col) && any(!is.na(col))) {
      return(parse_flexible_date(col))
    }
  }
  
  return(as.Date(NA))
}

#' Parse dates in various Brazilian formats
parse_flexible_date <- function(date_vector) {
  if (is.null(date_vector)) return(as.Date(NA))
  
  # Try different date formats common in Brazilian APIs
  date_formats <- c(
    "%Y-%m-%d",           # ISO format
    "%d/%m/%Y",           # Brazilian format
    "%d-%m-%Y",           # Alternative Brazilian
    "%Y-%m-%d %H:%M:%S",  # Datetime
    "%d/%m/%Y %H:%M:%S",  # Brazilian datetime
    "%Y%m%d"              # Compact format
  )
  
  parsed_dates <- rep(as.Date(NA), length(date_vector))
  
  for (fmt in date_formats) {
    mask <- is.na(parsed_dates)
    if (any(mask)) {
      tryCatch({
        parsed_dates[mask] <- as.Date(date_vector[mask], format = fmt)
      }, error = function(e) {
        # Continue to next format
      })
    }
  }
  
  return(parsed_dates)
}

#' Extract document number from title
extract_number_from_title <- function(title) {
  if (is.na(title)) return(NA_character_)
  
  # Look for patterns like "nº 123/2020" or "123/2020"
  number_pattern <- "n[ºo\\.°]?\\s*(\\d+[/\\-]?\\d*)"
  matches <- str_extract(title, number_pattern)
  
  if (!is.na(matches)) {
    return(str_extract(matches, "\\d+[/\\-]?\\d*"))
  }
  
  # Fallback: just look for number/year pattern
  fallback <- str_extract(title, "\\d+[/\\-]\\d{4}")
  return(fallback)
}

#' Extract state from authority field (LexML format)
extract_state_from_authority <- function() {
  if (exists("authority") && !is.na(authority)) {
    # LexML authority format: br.sp.gov or br.rj.gov
    state_match <- str_extract(authority, "br\\.([a-z]{2})\\.")
    if (!is.na(state_match)) {
      return(toupper(str_extract(state_match, "[a-z]{2}")))
    }
  }
  return(NA_character_)
}

#' Extract municipality from authority field
extract_municipality_from_authority <- function() {
  if (exists("authority") && !is.na(authority)) {
    # LexML authority format: br.sp.saopaulo
    parts <- str_split(authority, "\\.")[[1]]
    if (length(parts) >= 3) {
      return(str_to_title(parts[3]))
    }
  }
  return(NA_character_)
}

#' Build document URL based on source and identifiers
build_document_url <- function() {
  # This would build URLs based on known patterns for each source
  return(NA_character_)
}

#' Clean and normalize text
clean_text <- function(text) {
  if (is.na(text)) return(NA_character_)
  
  text %>%
    # Remove extra whitespace
    str_squish() %>%
    # Fix encoding issues
    replace_html() %>%
    # Standardize quotes
    str_replace_all(""", '"') %>%
    str_replace_all(""", '"') %>%
    # Remove control characters
    str_replace_all("[\\r\\n\\t]+", " ") %>%
    # Truncate if too long
    str_trunc(1000)
}

#' Create unique identifier for deduplication
create_unique_id <- function(title, number, date, source) {
  paste(
    digest::digest(tolower(str_squish(title))),
    number %||% "",
    as.character(date),
    source,
    sep = "_"
  ) %>%
    str_replace_all("[^a-zA-Z0-9_]", "")
}

#' Create academic citation
create_academic_citation <- function(title, type, number, date, author, source) {
  if (is.na(title) || is.na(date)) return(NA_character_)
  
  year <- year(as.Date(date))
  
  # Federal sources
  if (str_detect(source, "Câmara")) {
    return(sprintf("BRASIL. Câmara dos Deputados. %s. %s nº %s, de %s. Brasília: Câmara dos Deputados, %d.",
                  title, str_to_title(type), number %||% "s/n", 
                  format(as.Date(date), "%d %b %Y"), year))
  }
  
  if (str_detect(source, "Senado")) {
    return(sprintf("BRASIL. Senado Federal. %s. %s nº %s, de %s. Brasília: Senado Federal, %d.",
                  title, str_to_title(type), number %||% "s/n", 
                  format(as.Date(date), "%d %b %Y"), year))
  }
  
  # Generic citation
  return(sprintf("%s. %s. %s nº %s, de %s. %s, %d.",
                toupper(author %||% source), title, str_to_title(type), 
                number %||% "s/n", format(as.Date(date), "%d %b %Y"), year))
}

#' Extract keywords from title and summary
extract_keywords <- function(title, summary) {
  if (is.na(title)) return(NA_character_)
  
  text <- paste(title, summary %||% "", sep = " ")
  
  # Common legislative keywords in Portuguese
  keywords <- c(
    "transporte", "trânsito", "veículos", "rodovia", "estrada",
    "mobilidade", "logística", "frete", "carga", "passageiro",
    "público", "privado", "concessão", "permissão", "autorização",
    "fiscalização", "multa", "infração", "licença", "registro",
    "segurança", "sinalização", "equipamento", "tecnologia",
    "sustentabilidade", "meio ambiente", "poluição"
  )
  
  found_keywords <- keywords[str_detect(tolower(text), keywords)]
  
  if (length(found_keywords) > 0) {
    return(paste(found_keywords, collapse = ", "))
  }
  
  return(NA_character_)
}

#' Validate legislative data quality
validate_legislative_data <- function(data) {
  if (is.null(data) || !is.data.frame(data) || nrow(data) == 0) {
    return(data)
  }
  
  # Quality checks
  valid_data <- data %>%
    filter(
      # Basic validation
      !is.na(titulo),
      nchar(titulo) >= 10,
      !is.na(data),
      data >= as.Date("1988-10-05"),  # Constitution date
      data <= Sys.Date(),
      
      # Content validation
      !str_detect(tolower(titulo), "^(test|exemplo|sample)"),
      !str_detect(tolower(fonte_original), "mock|fake|test")
    )
  
  removed_count <- nrow(data) - nrow(valid_data)
  if (removed_count > 0) {
    flog.info("Validation removed %d invalid records", removed_count)
  }
  
  return(valid_data)
}

#' Remove duplicate records
remove_duplicates <- function(data) {
  if (is.null(data) || !is.data.frame(data) || nrow(data) == 0) {
    return(data)
  }
  
  # Remove exact duplicates
  deduped <- data %>%
    distinct(titulo, numero, data, .keep_all = TRUE)
  
  # Remove near-duplicates (similar titles)
  if (nrow(deduped) > 1) {
    deduped <- deduped %>%
      group_by(titulo_clean = tolower(str_squish(titulo))) %>%
      slice_head(n = 1) %>%
      ungroup() %>%
      select(-titulo_clean)
  }
  
  removed_count <- nrow(data) - nrow(deduped)
  if (removed_count > 0) {
    flog.info("Deduplication removed %d duplicate records", removed_count)
  }
  
  return(deduped)
}

#' Add geographic enrichment
enrich_geographic_data <- function(data, geographic_data = NULL) {
  if (is.null(data) || nrow(data) == 0) {
    return(data)
  }
  
  # Add state names, regions, etc.
  state_info <- data.frame(
    estado = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
               "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
               "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    estado_nome = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                   "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                   "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                   "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", 
                   "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima", 
                   "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
    regiao = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste",
               "Centro-Oeste", "Sudeste", "Centro-Oeste", "Nordeste",
               "Centro-Oeste", "Centro-Oeste", "Sudeste", "Norte", "Nordeste",
               "Sul", "Nordeste", "Nordeste", "Sudeste", "Nordeste",
               "Sul", "Norte", "Norte", "Sul", "Sudeste", "Nordeste", "Norte"),
    stringsAsFactors = FALSE
  )
  
  enriched <- data %>%
    left_join(state_info, by = "estado") %>%
    mutate(
      estado_nome = coalesce(estado_nome, estado),
      regiao = coalesce(regiao, "Não identificado")
    )
  
  return(enriched)
}