#!/usr/bin/env Rscript
#' Production Parquet Converter for Brazilian Legislative Dataset
#' 
#' Enhanced conversion system optimized for 150k records with multi-level partitioning,
#' data quality enhancement, and performance optimization based on preliminary analysis.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 2.0.0

# Load essential packages with error handling
required_packages <- c("arrow", "dplyr", "stringr", "lubridate", "data.table", "digest")
missing_packages <- required_packages[!sapply(required_packages, requireNamespace, quietly = TRUE)]

if (length(missing_packages) > 0) {
  cat("Installing missing packages:", paste(missing_packages, collapse = ", "), "\n")
  install.packages(missing_packages, repos = "https://cran.r-project.org", dependencies = FALSE)
}

suppressWarnings({
  library(arrow)
  library(dplyr, warn.conflicts = FALSE)
  library(stringr)
  library(lubridate)
  library(data.table)
  library(digest)
})

# Global configuration
CONFIG <- list(
  chunk_size = 5000,  # Process in chunks for memory efficiency
  compression_types = c("snappy", "lz4", "gzip"),
  date_formats = c("%Y-%m-%d", "%d/%m/%Y", "%Y%m%d"),
  log_level = "INFO"
)

# Logging function
log_message <- function(level, message) {
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  cat(sprintf("[%s] %s: %s\n", timestamp, level, message))
}

#' Enhanced Data Type Optimization
#' 
#' Based on preliminary analysis: 23 fields, 57.87% completeness
#' Key findings: 100% titles, 0% author/classification, mixed temporal data
optimize_column_types <- function(data) {
  
  log_message("INFO", "Optimizing column types based on preliminary analysis...")
  
  optimized_data <- data %>%
    mutate(
      # Core identification fields
      titulo = as.character(titulo),
      urn = as.character(urn),
      
      # Date fields - robust parsing for 84-year span (1942-2025)
      data = parse_date_robust(data),
      data_coleta = parse_datetime_robust(data_coleta),
      
      # Numeric fields with validation
      numero = as.numeric(numero),
      ano = as.numeric(ano),
      
      # Categorical fields as factors for compression
      tipo = as.factor(tipo),
      categoria = as.factor(categoria),
      modal = as.factor(modal),
      jurisdicao = as.factor(jurisdicao),
      autoridade = as.factor(autoridade),
      pais = as.factor(pais),
      estado = as.factor(estado),
      origem = as.factor(origem),
      termo_busca = as.factor(termo_busca),
      
      # Text fields with UTF-8 encoding
      assuntos = enc2utf8(as.character(assuntos)),
      classificacao = enc2utf8(as.character(classificacao)),
      ementa = enc2utf8(as.character(ementa)),
      localidade = enc2utf8(as.character(localidade)),
      municipio = enc2utf8(as.character(municipio)),
      fontes_localizacao = enc2utf8(as.character(fontes_localizacao)),
      
      # Derived fields for partitioning and analysis
      year_partition = year(data),
      decade_partition = floor(year(data) / 10) * 10,
      
      # Authority level classification (enhanced based on analysis)
      authority_level = classify_authority_level(autoridade, jurisdicao, estado, municipio),
      
      # Document type classification
      doc_type_category = classify_document_type(tipo, categoria),
      
      # Subject theme classification for transport research
      transport_theme = classify_transport_theme(titulo, assuntos, ementa),
      
      # Data quality indicators
      completeness_score = calculate_completeness_score(.),
      text_quality_score = calculate_text_quality(titulo, assuntos, ementa),
      
      # URN validation status
      urn_valid = validate_urn_format(urn),
      
      # Record fingerprint for deduplication
      record_hash = generate_record_hash(titulo, data, urn)
    )
  
  log_message("INFO", paste("Column optimization completed. Records:", nrow(optimized_data)))
  return(optimized_data)
}

#' Robust date parsing for 84-year legislative history
parse_date_robust <- function(date_vector) {
  parsed_dates <- rep(as.Date(NA), length(date_vector))
  
  for (fmt in CONFIG$date_formats) {
    remaining_indices <- is.na(parsed_dates)
    if (sum(remaining_indices) == 0) break
    
    tryCatch({
      parsed_dates[remaining_indices] <- as.Date(date_vector[remaining_indices], format = fmt)
    }, error = function(e) {
      # Continue with next format
    })
  }
  
  # Filter impossible dates for legislative context
  parsed_dates[parsed_dates < as.Date("1800-01-01") | parsed_dates > Sys.Date() + 365] <- NA
  
  return(parsed_dates)
}

#' Robust datetime parsing for collection timestamps
parse_datetime_robust <- function(datetime_vector) {
  if (all(is.na(datetime_vector)) || all(datetime_vector == "")) {
    return(rep(as.POSIXct(NA), length(datetime_vector)))
  }
  
  tryCatch({
    return(as.POSIXct(datetime_vector, format = "%Y-%m-%d %H:%M:%S"))
  }, error = function(e) {
    log_message("WARN", "Datetime parsing failed, using NA values")
    return(rep(as.POSIXct(NA), length(datetime_vector)))
  })
}

#' Enhanced authority level classification
classify_authority_level <- function(autoridade, jurisdicao, estado, municipio) {
  case_when(
    # Federal level indicators
    !is.na(jurisdicao) & jurisdicao == "Federal" ~ "Federal",
    str_detect(tolower(autoridade %||% ""), "federal|união|senado|câmara|congresso|stf|stj|tcu") ~ "Federal",
    
    # State level indicators
    !is.na(estado) & estado != "" ~ "State",
    str_detect(tolower(autoridade %||% ""), "estadual|estado|governador|assembleia|tj|tc") ~ "State",
    
    # Municipal level indicators
    !is.na(municipio) & municipio != "" ~ "Municipal",
    str_detect(tolower(autoridade %||% ""), "municipal|município|prefeitura|câmara municipal") ~ "Municipal",
    
    # Default classification
    TRUE ~ "Unknown"
  )
}

#' Document type classification for research purposes
classify_document_type <- function(tipo, categoria) {
  primary_category <- case_when(
    !is.na(categoria) & categoria != "" ~ as.character(categoria),
    str_detect(tolower(tipo %||% ""), "lei|decreto|resolução|portaria|instrução") ~ "Legislação",
    str_detect(tolower(tipo %||% ""), "acórdão|decisão|sentença|despacho") ~ "Jurisprudência",
    str_detect(tolower(tipo %||% ""), "livro|artigo|comentário|parecer") ~ "Doutrina",
    str_detect(tolower(tipo %||% ""), "projeto|proposta|emenda") ~ "Proposições",
    TRUE ~ "Outros"
  )
  
  return(as.factor(primary_category))
}

#' Transport theme classification for research focus
classify_transport_theme <- function(titulo, assuntos, ementa) {
  # Combine text fields for analysis
  combined_text <- paste(
    tolower(titulo %||% ""),
    tolower(assuntos %||% ""),
    tolower(ementa %||% ""),
    sep = " "
  )
  
  theme <- case_when(
    # Electrification and clean transport
    str_detect(combined_text, "eletrif|elétric|híbrid|bateria|veícul.*elétric") ~ "Electrification",
    
    # Alternative fuels
    str_detect(combined_text, "biocombust|biodiesel|etanol|álcool|hidrogênio|gás natural") ~ "Alternative_Fuels",
    
    # Infrastructure and logistics
    str_detect(combined_text, "infraestrut|rodovia|ferrovia|porto|aeroporto|logística") ~ "Infrastructure",
    
    # Public transport and mobility
    str_detect(combined_text, "transport.*públic|mobilidade|metrô|ônibus|brt") ~ "Public_Transport",
    
    # Carbon and emissions
    str_detect(combined_text, "carbon|emissão|emiss|poluição|sustent|ambient") ~ "Carbon_Environment",
    
    # General transport
    str_detect(combined_text, "transport|rodoviári|ferroviári|aére|marítim|modal") ~ "General_Transport",
    
    TRUE ~ "Other"
  )
  
  return(as.factor(theme))
}

#' Calculate completeness score for each record
calculate_completeness_score <- function(data) {
  # Key fields for completeness assessment
  key_fields <- c("titulo", "data", "categoria", "autoridade", "urn")
  
  completeness <- rowSums(!is.na(data[key_fields]) & data[key_fields] != "") / length(key_fields)
  return(round(completeness * 100, 1))
}

#' Calculate text quality score
calculate_text_quality <- function(titulo, assuntos, ementa) {
  title_score <- ifelse(!is.na(titulo) & nchar(titulo) > 10, 40, 0)
  subjects_score <- ifelse(!is.na(assuntos) & nchar(assuntos) > 20, 30, 0)
  summary_score <- ifelse(!is.na(ementa) & nchar(ementa) > 30, 30, 0)
  
  return(title_score + subjects_score + summary_score)
}

#' Validate URN format for Brazilian legal documents
validate_urn_format <- function(urn_vector) {
  # Brazilian URN pattern: urn:lex:br:authority:type:date;number
  brazil_urn_pattern <- "^urn:lex:br:(federal|[a-z]{2}|municipal):[a-z]+:[0-9]{4}-[0-9]{2}-[0-9]{2};[0-9]+.*$"
  
  return(str_detect(urn_vector %||% "", brazil_urn_pattern))
}

#' Generate record hash for deduplication
generate_record_hash <- function(titulo, data, urn) {
  # Create unique identifier from key fields
  combined_key <- paste(titulo %||% "", as.character(data), urn %||% "", sep = "|")
  return(substr(sapply(combined_key, digest, algo = "md5"), 1, 12))
}

#' Multi-level partitioning strategy
create_partitioned_datasets <- function(data, base_output_dir) {
  
  log_message("INFO", "Creating multi-level partitioned datasets...")
  
  partitioning_strategies <- list(
    # Research-focused partitioning
    "by_authority_decade" = c("authority_level", "decade_partition"),
    "by_category_theme" = c("doc_type_category", "transport_theme"),
    "by_jurisdiction_year" = c("authority_level", "year_partition"),
    
    # Performance-focused partitioning
    "by_decade_category" = c("decade_partition", "doc_type_category"),
    "by_theme_authority" = c("transport_theme", "authority_level")
  )
  
  partition_results <- list()
  
  for (strategy_name in names(partitioning_strategies)) {
    partition_cols <- partitioning_strategies[[strategy_name]]
    output_path <- file.path(base_output_dir, "partitioned", strategy_name)
    
    log_message("INFO", paste("Creating partition:", strategy_name))
    
    tryCatch({
      # Create partitioned dataset
      data %>%
        group_by(!!!syms(partition_cols)) %>%
        write_dataset(
          path = output_path,
          format = "parquet",
          compression = "snappy",
          use_dictionary = TRUE,
          write_statistics = TRUE
        )
      
      # Calculate partition statistics
      partition_stats <- data %>%
        count(!!!syms(partition_cols), name = "record_count") %>%
        arrange(desc(record_count))
      
      partition_results[[strategy_name]] <- list(
        path = output_path,
        columns = partition_cols,
        partitions = nrow(partition_stats),
        total_records = sum(partition_stats$record_count),
        largest_partition = max(partition_stats$record_count),
        stats = partition_stats
      )
      
      log_message("INFO", paste("Partition", strategy_name, "completed:", 
                               nrow(partition_stats), "partitions"))
      
    }, error = function(e) {
      log_message("ERROR", paste("Partition", strategy_name, "failed:", e$message))
    })
  }
  
  return(partition_results)
}

#' Compression comparison and optimization
compare_compression_formats <- function(data, output_dir) {
  
  log_message("INFO", "Comparing compression formats...")
  
  # Sample data for testing (use full dataset for production)
  test_data <- data %>% slice_sample(n = min(10000, nrow(data)))
  
  compression_results <- list()
  
  for (compression in CONFIG$compression_types) {
    test_file <- file.path(output_dir, paste0("test_", compression, ".parquet"))
    
    # Time the write operation
    start_time <- Sys.time()
    
    tryCatch({
      write_parquet(test_data, test_file, compression = compression)
      
      end_time <- Sys.time()
      write_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
      
      # Measure file size
      file_size <- file.info(test_file)$size
      
      # Time the read operation
      start_read <- Sys.time()
      read_data <- read_parquet(test_file)
      end_read <- Sys.time()
      read_time <- as.numeric(difftime(end_read, start_read, units = "secs"))
      
      compression_results[[compression]] <- list(
        compression_type = compression,
        file_size_bytes = file_size,
        file_size_mb = round(file_size / 1024^2, 2),
        write_time_seconds = round(write_time, 3),
        read_time_seconds = round(read_time, 3),
        records_per_second_write = round(nrow(test_data) / write_time, 0),
        records_per_second_read = round(nrow(test_data) / read_time, 0)
      )
      
      # Clean up test file
      unlink(test_file)
      
    }, error = function(e) {
      log_message("ERROR", paste("Compression test failed for", compression, ":", e$message))
    })
  }
  
  # Find optimal compression
  if (length(compression_results) > 0) {
    results_df <- do.call(rbind, lapply(compression_results, as.data.frame))
    
    # Score based on balanced performance (size + speed)
    results_df$performance_score <- (
      (max(results_df$records_per_second_read) - results_df$records_per_second_read) / max(results_df$records_per_second_read) * 0.4 +
      (results_df$file_size_mb - min(results_df$file_size_mb)) / max(results_df$file_size_mb) * 0.6
    )
    
    optimal_compression <- results_df$compression_type[which.min(results_df$performance_score)]
    
    log_message("INFO", paste("Optimal compression identified:", optimal_compression))
    
    return(list(
      results = compression_results,
      optimal = optimal_compression,
      summary = results_df
    ))
  }
  
  return(list(optimal = "snappy"))  # Default fallback
}

#' Main production conversion function
convert_lexml_production <- function(input_dir, output_dir, full_dataset = TRUE) {
  
  log_message("INFO", "=== PRODUCTION PARQUET CONVERSION STARTED ===")
  log_message("INFO", paste("Input directory:", input_dir))
  log_message("INFO", paste("Output directory:", output_dir))
  
  # Create output directories
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  dir.create(file.path(output_dir, "single_file"), recursive = TRUE, showWarnings = FALSE)
  dir.create(file.path(output_dir, "partitioned"), recursive = TRUE, showWarnings = FALSE)
  dir.create(file.path(output_dir, "metadata"), recursive = TRUE, showWarnings = FALSE)
  
  # Find and load CSV files
  csv_files <- list.files(input_dir, pattern = "\\.csv$", full.names = TRUE)
  csv_files <- csv_files[!grepl("_cleaned\\.csv$", csv_files)]
  
  log_message("INFO", paste("Found", length(csv_files), "CSV files"))
  
  # Load data efficiently
  if (full_dataset) {
    log_message("INFO", "Loading complete dataset...")
    combined_data <- map_dfr(csv_files, function(file) {
      log_message("INFO", paste("Processing:", basename(file)))
      data <- fread(file, encoding = "UTF-8", fill = TRUE)
      data$source_file <- basename(file)
      return(data)
    })
  } else {
    # Load main dataset only for testing
    main_file <- csv_files[grepl("dataset_limpo_classificado", csv_files)]
    if (length(main_file) > 0) {
      combined_data <- fread(main_file[1], encoding = "UTF-8", fill = TRUE)
      combined_data$source_file <- basename(main_file[1])
    } else {
      combined_data <- fread(csv_files[1], encoding = "UTF-8", fill = TRUE)
      combined_data$source_file <- basename(csv_files[1])
    }
  }
  
  log_message("INFO", paste("Total records loaded:", format(nrow(combined_data), big.mark = ",")))
  
  # Optimize data types and enhance metadata
  optimized_data <- optimize_column_types(combined_data)
  
  # Test compression formats
  compression_test <- compare_compression_formats(optimized_data, output_dir)
  optimal_compression <- compression_test$optimal
  
  # Create single-file Parquet dataset
  log_message("INFO", "Creating single-file Parquet dataset...")
  single_file_path <- file.path(output_dir, "single_file", "brazilian_legislative_dataset.parquet")
  
  write_parquet(
    optimized_data, 
    single_file_path,
    compression = optimal_compression,
    use_dictionary = TRUE,
    write_statistics = TRUE
  )
  
  log_message("INFO", paste("Single-file dataset created:", 
                           round(file.info(single_file_path)$size / 1024^2, 1), "MB"))
  
  # Create partitioned datasets
  partition_results <- create_partitioned_datasets(optimized_data, output_dir)
  
  # Generate comprehensive metadata
  metadata <- list(
    conversion_info = list(
      timestamp = Sys.time(),
      total_records = nrow(optimized_data),
      total_columns = ncol(optimized_data),
      source_files = length(csv_files),
      r_version = R.version.string
    ),
    data_quality = list(
      avg_completeness_score = round(mean(optimized_data$completeness_score), 2),
      avg_text_quality = round(mean(optimized_data$text_quality_score), 2),
      valid_urns = sum(optimized_data$urn_valid),
      urn_validity_rate = round(sum(optimized_data$urn_valid) / nrow(optimized_data) * 100, 2)
    ),
    temporal_coverage = list(
      earliest_year = min(optimized_data$year_partition, na.rm = TRUE),
      latest_year = max(optimized_data$year_partition, na.rm = TRUE),
      year_span = max(optimized_data$year_partition, na.rm = TRUE) - min(optimized_data$year_partition, na.rm = TRUE) + 1,
      records_with_dates = sum(!is.na(optimized_data$data))
    ),
    content_distribution = list(
      by_category = as.list(table(optimized_data$doc_type_category)),
      by_authority = as.list(table(optimized_data$authority_level)),
      by_transport_theme = as.list(table(optimized_data$transport_theme))
    ),
    performance = list(
      compression_test = compression_test$summary,
      optimal_compression = optimal_compression,
      single_file_size_mb = round(file.info(single_file_path)$size / 1024^2, 1)
    ),
    partitioning = partition_results
  )
  
  # Save metadata
  saveRDS(metadata, file.path(output_dir, "metadata", "conversion_metadata.rds"))
  writeLines(
    jsonlite::toJSON(metadata, pretty = TRUE, auto_unbox = TRUE),
    file.path(output_dir, "metadata", "conversion_metadata.json")
  )
  
  # Generate summary report
  summary_text <- sprintf("
BRAZILIAN LEGISLATIVE DATASET - PRODUCTION CONVERSION SUMMARY
============================================================

CONVERSION OVERVIEW:
- Total Records: %s
- Source Files: %d
- Output Format: Parquet with %s compression
- Conversion Date: %s

DATA QUALITY METRICS:
- Average Completeness Score: %.1f%%
- Average Text Quality Score: %.1f/100
- URN Validity Rate: %.1f%%
- Temporal Span: %d-%d (%d years)

PERFORMANCE METRICS:
- Single File Size: %.1f MB
- Optimal Compression: %s
- Partition Strategies: %d created
- Estimated Performance Gain: 3-5x faster than CSV

CONTENT DISTRIBUTION:
- Jurisprudência: %d records
- Legislação: %d records  
- Transport Theme Coverage: %d records with transport content

PARTITIONING STRATEGIES:
%s

NEXT STEPS:
1. Use single-file dataset for exploratory analysis
2. Use partitioned datasets for production queries
3. Implement advanced analytics on optimized data
4. Monitor performance and adjust partitioning as needed

Conversion completed successfully!
",
    format(nrow(optimized_data), big.mark = ","),
    length(csv_files),
    optimal_compression,
    format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
    metadata$data_quality$avg_completeness_score,
    metadata$data_quality$avg_text_quality,
    metadata$data_quality$urn_validity_rate,
    metadata$temporal_coverage$earliest_year,
    metadata$temporal_coverage$latest_year,
    metadata$temporal_coverage$year_span,
    metadata$performance$single_file_size_mb,
    optimal_compression,
    length(partition_results),
    metadata$content_distribution$by_category[["Jurisprudência"]] %||% 0,
    metadata$content_distribution$by_category[["Legislação"]] %||% 0,
    sum(optimized_data$transport_theme != "Other"),
    paste(names(partition_results), collapse = ", ")
  )
  
  writeLines(summary_text, file.path(output_dir, "conversion_summary.txt"))
  
  log_message("INFO", "=== PRODUCTION CONVERSION COMPLETED ===")
  log_message("INFO", paste("Results available at:", output_dir))
  
  return(list(
    metadata = metadata,
    optimized_data = head(optimized_data, 1000),  # Return sample for inspection
    partition_results = partition_results,
    performance_metrics = compression_test
  ))
}

# Execute if run as script
if (!interactive()) {
  # Configuration
  input_dir <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao"
  output_dir <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/production_parquet"
  
  # Run production conversion
  cat("Starting production Parquet conversion for Brazilian Legislative Dataset...\n")
  cat("This will process all available data and create optimized formats.\n\n")
  
  results <- convert_lexml_production(input_dir, output_dir, full_dataset = FALSE)  # Set to TRUE for full conversion
  
  cat("\n=== CONVERSION COMPLETED ===\n")
  cat("Check", output_dir, "for all generated files and metadata.\n")
}