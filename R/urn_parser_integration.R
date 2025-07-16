# URN Parser Integration Module for R Shiny App
# Handles parsed URN components and provides analysis functions

library(dplyr)
library(ggplot2)
library(plotly)
library(DT)
library(leaflet)
library(jsonlite)
library(futile.logger)

#' Load parsed URN data from CSV or database
#' @param data_source Path to CSV file or database connection
#' @param limit Maximum number of records to load
#' @return Data frame with parsed URN components
load_parsed_urn_data <- function(data_source = "./data_current/processed/lexml_parsed_enhanced.csv", limit = NULL) {
  
  flog.info("Loading parsed URN data from: %s", data_source)
  
  tryCatch({
    if (file.exists(data_source)) {
      # Load from CSV file
      data <- read.csv(data_source, stringsAsFactors = FALSE)
      flog.info("Loaded %d records from CSV file", nrow(data))
    } else {
      # Fallback to sample data if file doesn't exist
      flog.warn("Data file not found, using sample data")
      data <- create_sample_urn_data()
    }
    
    # Apply limit if specified
    if (!is.null(limit) && limit > 0) {
      data <- head(data, limit)
      flog.info("Limited to %d records", nrow(data))
    }
    
    # Ensure required columns exist
    required_cols <- c("urn", "urn_type", "country", "state", "municipality", 
                      "justice", "region", "court_class", "document_type_full", 
                      "promulgation_date", "document_description")
    
    missing_cols <- setdiff(required_cols, names(data))
    if (length(missing_cols) > 0) {
      flog.warn("Missing columns: %s", paste(missing_cols, collapse = ", "))
      # Add missing columns with NA values
      for (col in missing_cols) {
        data[[col]] <- NA
      }
    }
    
    # Clean and standardize data
    data <- clean_urn_data(data)
    
    return(data)
    
  }, error = function(e) {
    flog.error("Error loading parsed URN data: %s", e$message)
    return(create_sample_urn_data())
  })
}

#' Clean and standardize parsed URN data
#' @param data Raw data frame
#' @return Cleaned data frame
clean_urn_data <- function(data) {
  
  # Convert date columns
  if ("promulgation_date" %in% names(data)) {
    data$promulgation_date <- as.Date(data$promulgation_date, format = "%d-%m-%Y")
  }
  
  # Standardize URN type
  data$urn_type <- ifelse(is.na(data$urn_type), "unknown", tolower(data$urn_type))
  
  # Clean state names for mapping
  if ("state" %in% names(data)) {
    data$state_clean <- clean_state_names(data$state)
  }
  
  # Add derived columns
  data$year <- ifelse(is.na(data$promulgation_date), NA, format(data$promulgation_date, "%Y"))
  data$days_since_promulgation <- ifelse(is.na(data$promulgation_date), NA, 
                                        as.numeric(Sys.Date() - data$promulgation_date))
  
  # Extract document type for analysis
  if ("document_type_full" %in% names(data)) {
    data$document_type_simple <- extract_simple_document_type(data$document_type_full)
  }
  
  return(data)
}

#' Clean state names for consistency
#' @param state_names Vector of state names
#' @return Cleaned state names
clean_state_names <- function(state_names) {
  # Map common variations to standard names
  state_mapping <- c(
    "sao.paulo" = "São Paulo",
    "rio.de.janeiro" = "Rio de Janeiro", 
    "minas.gerais" = "Minas Gerais",
    "rio.grande.do.sul" = "Rio Grande do Sul",
    "santa.catarina" = "Santa Catarina",
    "distrito.federal" = "Distrito Federal",
    "espirito.santo" = "Espírito Santo",
    "mato.grosso" = "Mato Grosso",
    "mato.grosso.do.sul" = "Mato Grosso do Sul",
    "rio.grande.do.norte" = "Rio Grande do Norte"
  )
  
  cleaned <- ifelse(tolower(state_names) %in% names(state_mapping),
                   state_mapping[tolower(state_names)],
                   state_names)
  
  return(cleaned)
}

#' Extract simple document type from full description
#' @param full_types Vector of full document type descriptions
#' @return Simplified document types
extract_simple_document_type <- function(full_types) {
  
  simple_types <- sapply(full_types, function(x) {
    if (is.na(x)) return("Unknown")
    
    x_lower <- tolower(x)
    
    if (grepl("^lei", x_lower)) return("Lei")
    if (grepl("^decreto", x_lower)) return("Decreto")
    if (grepl("^resolução", x_lower)) return("Resolução")
    if (grepl("^acórdão", x_lower)) return("Acórdão")
    if (grepl("^medida provisória", x_lower)) return("Medida Provisória")
    if (grepl("^portaria", x_lower)) return("Portaria")
    if (grepl("^instrução normativa", x_lower)) return("Instrução Normativa")
    
    # Extract first word as fallback
    first_word <- strsplit(x, " ")[[1]][1]
    return(tools::toTitleCase(first_word))
  })
  
  return(unname(simple_types))
}

#' Create sample URN data for testing
#' @return Sample data frame
create_sample_urn_data <- function() {
  
  flog.info("Creating sample URN data for testing")
  
  sample_data <- data.frame(
    urn = c(
      "urn:lex:br;minas.gerais;itabirito:municipal:lei:2008-12-05;2708",
      "urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491",
      "urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.6:acordao:2015-11-19;00008058020145010301",
      "urn:lex:br:federal:decreto:1976-06-09;77789",
      "urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;airr:2013-04-17;340-2010-130-15-0"
    ),
    urn_type = c("legislation", "legislation", "jurisprudence", "legislation", "jurisprudence"),
    country = rep("Brasil", 5),
    state = c("Minas Gerais", "São Paulo", NA, NA, NA),
    municipality = c("Itabirito", NA, NA, NA, NA),
    justice = c(NA, NA, "Justiça do Trabalho", NA, "Tribunal Superior do Trabalho"),
    region = c(NA, NA, "1ª região", NA, NA),
    court_class = c(NA, NA, "Tribunal Regional do Trabalho, 6ª turma", NA, "Tribunal Superior do Trabalho, 1ª turma"),
    document_type_full = c(
      "Lei Municipal 2708",
      "Decreto Estadual 60491", 
      "Acórdão número 00008058020145010301",
      "Decreto Federal 77789",
      "Acórdão (AIRR) número 340-2010-130-15-0"
    ),
    promulgation_date = as.Date(c("2008-12-05", "2014-05-26", "2015-11-19", "1976-06-09", "2013-04-17")),
    document_description = c(
      "Lei Municipal 2708, promulgada em 05-12-2008, Município de Itabirito, Estado de Minas Gerais, Brasil",
      "Decreto Estadual 60491, promulgada em 26-05-2014, Estado de São Paulo, Brasil",
      "Acórdão número 00008058020145010301, publicado em 19-11-2015, Tribunal Regional do Trabalho, 6ª turma, da 1ª região, Justiça do Trabalho",
      "Decreto Federal 77789, promulgada em 09-06-1976, Brasil",
      "Acórdão (AIRR) número 340-2010-130-15-0, publicado em 17-04-2013, Tribunal Superior do Trabalho, 1ª turma"
    ),
    title = c(
      "Lei sobre transporte urbano municipal",
      "Decreto regulamentando transporte escolar",
      "Acórdão sobre direitos trabalhistas",
      "Decreto sobre transporte rodoviário",
      "Acórdão em recurso de revista"
    ),
    stringsAsFactors = FALSE
  )
  
  # Add derived columns
  sample_data <- clean_urn_data(sample_data)
  
  return(sample_data)
}

#' Generate URN type distribution plot
#' @param data Parsed URN data
#' @return ggplot object
plot_urn_type_distribution <- function(data) {
  
  if (nrow(data) == 0) {
    return(ggplot() + 
           geom_text(aes(x = 1, y = 1, label = "Nenhum dado disponível")) +
           theme_void())
  }
  
  # Calculate distribution
  type_counts <- data %>%
    count(urn_type, name = "count") %>%
    mutate(
      percentage = round(count / sum(count) * 100, 1),
      label = paste0(tools::toTitleCase(urn_type), "\n(", count, " docs, ", percentage, "%)")
    )
  
  # Create plot
  p <- ggplot(type_counts, aes(x = "", y = count, fill = urn_type)) +
    geom_bar(stat = "identity", width = 1) +
    coord_polar(theta = "y") +
    geom_text(aes(label = label), position = position_stack(vjust = 0.5)) +
    scale_fill_manual(
      values = c("legislation" = "#3498db", "jurisprudence" = "#e74c3c", "unknown" = "#95a5a6"),
      labels = c("legislation" = "Legislação", "jurisprudence" = "Jurisprudência", "unknown" = "Desconhecido")
    ) +
    theme_void() +
    theme(
      legend.title = element_blank(),
      legend.position = "bottom"
    ) +
    labs(title = "Distribuição por Tipo de URN")
  
  return(p)
}

#' Generate temporal distribution plot
#' @param data Parsed URN data
#' @return ggplot object
plot_temporal_distribution <- function(data) {
  
  if (nrow(data) == 0 || all(is.na(data$year))) {
    return(ggplot() + 
           geom_text(aes(x = 1, y = 1, label = "Nenhum dado temporal disponível")) +
           theme_void())
  }
  
  # Calculate yearly distribution
  yearly_data <- data %>%
    filter(!is.na(year)) %>%
    count(year, urn_type, name = "count") %>%
    mutate(year = as.numeric(year))
  
  # Create plot
  p <- ggplot(yearly_data, aes(x = year, y = count, fill = urn_type)) +
    geom_bar(stat = "identity", position = "stack") +
    scale_fill_manual(
      values = c("legislation" = "#3498db", "jurisprudence" = "#e74c3c", "unknown" = "#95a5a6"),
      labels = c("legislation" = "Legislação", "jurisprudence" = "Jurisprudência", "unknown" = "Desconhecido")
    ) +
    labs(
      title = "Distribuição Temporal dos Documentos",
      x = "Ano",
      y = "Número de Documentos",
      fill = "Tipo"
    ) +
    theme_minimal() +
    theme(
      axis.text.x = element_text(angle = 45, hjust = 1),
      legend.position = "bottom"
    )
  
  return(p)
}

#' Generate state distribution plot for legislation
#' @param data Parsed URN data
#' @return ggplot object
plot_state_distribution <- function(data) {
  
  legislation_data <- data %>%
    filter(urn_type == "legislation", !is.na(state))
  
  if (nrow(legislation_data) == 0) {
    return(ggplot() + 
           geom_text(aes(x = 1, y = 1, label = "Nenhum dado estadual disponível")) +
           theme_void())
  }
  
  # Calculate state distribution
  state_counts <- legislation_data %>%
    count(state, name = "count") %>%
    arrange(desc(count)) %>%
    head(10)  # Top 10 states
  
  # Create plot
  p <- ggplot(state_counts, aes(x = reorder(state, count), y = count)) +
    geom_bar(stat = "identity", fill = "#3498db") +
    geom_text(aes(label = count), hjust = -0.1) +
    coord_flip() +
    labs(
      title = "Top 10 Estados - Legislação",
      x = "Estado",
      y = "Número de Documentos"
    ) +
    theme_minimal()
  
  return(p)
}

#' Generate justice type distribution plot for jurisprudence
#' @param data Parsed URN data
#' @return ggplot object
plot_justice_distribution <- function(data) {
  
  jurisprudence_data <- data %>%
    filter(urn_type == "jurisprudence", !is.na(justice))
  
  if (nrow(jurisprudence_data) == 0) {
    return(ggplot() + 
           geom_text(aes(x = 1, y = 1, label = "Nenhum dado de jurisprudência disponível")) +
           theme_void())
  }
  
  # Calculate justice type distribution
  justice_counts <- jurisprudence_data %>%
    count(justice, name = "count") %>%
    arrange(desc(count))
  
  # Create plot
  p <- ggplot(justice_counts, aes(x = reorder(justice, count), y = count)) +
    geom_bar(stat = "identity", fill = "#e74c3c") +
    geom_text(aes(label = count), hjust = -0.1) +
    coord_flip() +
    labs(
      title = "Distribuição por Tipo de Justiça",
      x = "Tipo de Justiça",
      y = "Número de Decisões"
    ) +
    theme_minimal()
  
  return(p)
}

#' Create data table for URN analysis
#' @param data Parsed URN data
#' @param type Filter by URN type ("legislation", "jurisprudence", or "all")
#' @return DT datatable object
create_urn_datatable <- function(data, type = "all") {
  
  # Filter by type if specified
  if (type != "all") {
    data <- data %>% filter(urn_type == type)
  }
  
  if (nrow(data) == 0) {
    return(DT::datatable(data.frame(Mensagem = "Nenhum dado disponível")))
  }
  
  # Select and rename columns for display
  display_data <- data %>%
    select(
      URN = urn,
      Tipo = urn_type,
      Descrição = document_description,
      Estado = state,
      Município = municipality,
      Justiça = justice,
      Região = region,
      Data = promulgation_date,
      Título = title
    ) %>%
    mutate(
      Tipo = case_when(
        Tipo == "legislation" ~ "Legislação",
        Tipo == "jurisprudence" ~ "Jurisprudência",
        TRUE ~ "Desconhecido"
      )
    )
  
  # Create datatable
  dt <- DT::datatable(
    display_data,
    options = list(
      pageLength = 25,
      scrollX = TRUE,
      autoWidth = TRUE,
      columnDefs = list(
        list(width = "200px", targets = c(0, 2)),  # URN and Description columns
        list(width = "100px", targets = c(1, 3, 4, 5, 6, 7))  # Other columns
      )
    ),
    filter = "top",
    rownames = FALSE
  ) %>%
    DT::formatDate("Data", method = "toLocaleDateString")
  
  return(dt)
}

#' Generate summary statistics for URN data
#' @param data Parsed URN data
#' @return Named list with summary statistics
generate_urn_summary <- function(data) {
  
  total_docs <- nrow(data)
  
  if (total_docs == 0) {
    return(list(
      total_documents = 0,
      legislation_count = 0,
      jurisprudence_count = 0,
      unique_states = 0,
      unique_municipalities = 0,
      date_range = "N/A"
    ))
  }
  
  # Basic counts
  legislation_count <- sum(data$urn_type == "legislation", na.rm = TRUE)
  jurisprudence_count <- sum(data$urn_type == "jurisprudence", na.rm = TRUE)
  
  # Geographic diversity
  unique_states <- length(unique(data$state[!is.na(data$state)]))
  unique_municipalities <- length(unique(data$municipality[!is.na(data$municipality)]))
  
  # Date range
  valid_dates <- data$promulgation_date[!is.na(data$promulgation_date)]
  if (length(valid_dates) > 0) {
    date_range <- paste(format(min(valid_dates), "%Y"), "-", format(max(valid_dates), "%Y"))
  } else {
    date_range <- "N/A"
  }
  
  # Most common document types
  top_types <- data %>%
    filter(!is.na(document_type_simple)) %>%
    count(document_type_simple, sort = TRUE) %>%
    head(3) %>%
    pull(document_type_simple)
  
  return(list(
    total_documents = total_docs,
    legislation_count = legislation_count,
    jurisprudence_count = jurisprudence_count,
    unique_states = unique_states,
    unique_municipalities = unique_municipalities,
    date_range = date_range,
    top_document_types = top_types,
    legislation_percentage = round(legislation_count / total_docs * 100, 1),
    jurisprudence_percentage = round(jurisprudence_count / total_docs * 100, 1)
  ))
}

#' Create geographic map data for legislation
#' @param data Parsed URN data
#' @return Data frame suitable for mapping
prepare_map_data <- function(data) {
  
  # Filter for legislation with state information
  map_data <- data %>%
    filter(urn_type == "legislation", !is.na(state)) %>%
    group_by(state_clean) %>%
    summarise(
      document_count = n(),
      latest_date = max(promulgation_date, na.rm = TRUE),
      earliest_date = min(promulgation_date, na.rm = TRUE),
      avg_days_since = round(mean(days_since_promulgation, na.rm = TRUE), 0),
      .groups = "drop"
    ) %>%
    rename(state = state_clean)
  
  return(map_data)
}

#' Export parsed URN data to CSV
#' @param data Parsed URN data
#' @param filename Output filename
#' @param type Filter by type ("all", "legislation", "jurisprudence")
#' @return TRUE if successful, FALSE otherwise
export_urn_data <- function(data, filename = "urn_analysis_export.csv", type = "all") {
  
  tryCatch({
    # Filter by type if specified
    if (type != "all") {
      data <- data %>% filter(urn_type == type)
    }
    
    # Ensure exports directory exists
    if (!dir.exists("exports")) {
      dir.create("exports", recursive = TRUE)
    }
    
    # Full path
    full_path <- file.path("exports", filename)
    
    # Write CSV
    write.csv(data, full_path, row.names = FALSE)
    
    flog.info("Exported %d records to %s", nrow(data), full_path)
    return(TRUE)
    
  }, error = function(e) {
    flog.error("Error exporting URN data: %s", e$message)
    return(FALSE)
  })
} 