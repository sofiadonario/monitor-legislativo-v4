#!/usr/bin/env Rscript
#' Brazilian Legislative Dataset - Phase 3: Data Integrity Checks and Analytical Validation
#' 
#' This script implements comprehensive data integrity checks and analytical validation
#' for the Brazilian legislative dataset, including URN format compliance, metadata
#' consistency validation, and analytical method validation.
#' 
#' @author Brazilian Legislative Analytics Framework
#' @date 2025-07-26
#' @version 1.0.0

# Load required libraries
suppressPackageStartupMessages({
  library(dplyr)
  library(stringr)
  library(lubridate)
  library(arrow)
  library(purrr)
  library(tibble)
  library(ggplot2)
  library(testthat)
  library(checkmate)
  library(validate)
  library(VIM)
  library(janitor)
  library(logger)
  library(digest)
  library(DBI)
  library(RSQLite)
})

# Set up logging
log_threshold(INFO)

#' Data Integrity Check Functions
#' ===============================

#' Validate URN format compliance across all records
#' @param data Legislative dataset
#' @return Detailed URN validation results
validate_urn_compliance <- function(data) {
  
  log_info("Validating URN format compliance...")
  
  # Brazilian URN pattern: urn:lex:br:authority:type:date;number
  base_pattern <- "^urn:lex:br:"
  full_pattern <- "^urn:lex:br:(federal|[a-z]{2}|municipal):[a-z]+:[0-9]{4}-[0-9]{2}-[0-9]{2};[0-9]+.*$"
  
  urn_validation <- data %>%
    mutate(
      urn_present = !is.na(urn) & urn != "",
      urn_starts_correctly = str_detect(urn, base_pattern),
      urn_full_format = str_detect(urn, full_pattern),
      
      # Extract URN components
      urn_authority = str_extract(urn, "urn:lex:br:([^:]+):", group = 1),
      urn_type = str_extract(urn, ":([a-z]+):[0-9]{4}", group = 1),
      urn_date = str_extract(urn, "([0-9]{4}-[0-9]{2}-[0-9]{2})", group = 1),
      urn_number = str_extract(urn, ";([0-9]+)", group = 1),
      
      # Validation flags
      authority_valid = urn_authority %in% c("federal", "municipal") | str_length(urn_authority) == 2,
      date_valid = !is.na(ymd(urn_date)),
      number_valid = !is.na(as.numeric(urn_number)),
      
      # Overall validation
      urn_completely_valid = urn_present & urn_full_format & authority_valid & date_valid & number_valid
    )
  
  # Summary statistics
  urn_summary <- urn_validation %>%
    summarise(
      total_records = n(),
      urns_present = sum(urn_present, na.rm = TRUE),
      urns_correctly_formatted = sum(urn_full_format, na.rm = TRUE),
      urns_completely_valid = sum(urn_completely_valid, na.rm = TRUE),
      
      # Compliance rates
      presence_rate = round(urns_present / total_records * 100, 2),
      format_compliance_rate = round(urns_correctly_formatted / urns_present * 100, 2),
      full_compliance_rate = round(urns_completely_valid / urns_present * 100, 2),
      
      # Common issues
      invalid_authorities = sum(!authority_valid & urn_present, na.rm = TRUE),
      invalid_dates = sum(!date_valid & urn_present, na.rm = TRUE),
      invalid_numbers = sum(!number_valid & urn_present, na.rm = TRUE)
    )
  
  # Identify problematic URNs
  problematic_urns <- urn_validation %>%
    filter(urn_present & !urn_completely_valid) %>%
    select(urn, titulo, autoridade, data, urn_authority, urn_type, urn_date, urn_number,
           authority_valid, date_valid, number_valid) %>%
    slice_head(n = 100)  # Top 100 problematic cases
  
  log_info("URN validation completed: {urn_summary$full_compliance_rate}% fully compliant")
  
  return(list(
    summary = urn_summary,
    detailed_validation = urn_validation,
    problematic_urns = problematic_urns
  ))
}

#' Cross-reference metadata consistency
#' @param data Legislative dataset
#' @return Metadata consistency analysis
check_metadata_consistency <- function(data) {
  
  log_info("Checking metadata consistency...")
  
  consistency_checks <- data %>%
    mutate(
      # Date consistency checks
      date_parsed = as.Date(data),
      year_from_date = year(date_parsed),
      year_from_urn = as.numeric(str_extract(urn, "([0-9]{4})", group = 1)),
      date_urn_consistent = is.na(year_from_urn) | abs(year_from_date - year_from_urn) <= 1,
      
      # Authority-jurisdiction alignment
      authority_jurisdiction_consistent = case_when(
        is.na(autoridade) | is.na(jurisdicao) ~ NA,
        str_detect(tolower(autoridade), "federal") & jurisdicao == "Federal" ~ TRUE,
        str_detect(tolower(autoridade), "estadual|estado") & jurisdicao != "Federal" ~ TRUE,
        str_detect(tolower(autoridade), "municipal|prefeitura") & jurisdicao != "Federal" ~ TRUE,
        TRUE ~ FALSE
      ),
      
      # Category-type consistency
      category_type_consistent = case_when(
        is.na(categoria) | is.na(tipo) ~ NA,
        categoria == "Legislação" & str_detect(tolower(tipo), "lei|decreto|resolução|portaria") ~ TRUE,
        categoria == "Jurisprudência" & str_detect(tolower(tipo), "acórdão|decisão|sentença") ~ TRUE,
        categoria == "Doutrina" & str_detect(tolower(tipo), "livro|artigo|comentário") ~ TRUE,
        TRUE ~ FALSE
      ),
      
      # Geographic consistency
      state_municipality_consistent = case_when(
        is.na(estado) | is.na(municipio) ~ TRUE,  # Missing data is not inconsistent
        estado != "" & municipio != "" ~ TRUE,   # Both present is fine
        estado == "" & municipio == "" ~ TRUE,   # Both absent is fine
        TRUE ~ FALSE  # One present, one absent is inconsistent
      ),
      
      # Text field completeness alignment
      text_completeness_score = rowSums(!is.na(select(., titulo, assuntos, ementa))),
      has_meaningful_text = text_completeness_score >= 1 & 
                           (nchar(coalesce(titulo, "")) > 10 | 
                            nchar(coalesce(assuntos, "")) > 20 |
                            nchar(coalesce(ementa, "")) > 20)
    )
  
  # Consistency summary
  consistency_summary <- consistency_checks %>%
    summarise(
      total_records = n(),
      
      # Date consistency
      date_urn_consistent_count = sum(date_urn_consistent, na.rm = TRUE),
      date_urn_inconsistent_count = sum(!date_urn_consistent, na.rm = TRUE),
      date_consistency_rate = round(date_urn_consistent_count / (date_urn_consistent_count + date_urn_inconsistent_count) * 100, 2),
      
      # Authority-jurisdiction consistency
      authority_jurisdiction_consistent_count = sum(authority_jurisdiction_consistent, na.rm = TRUE),
      authority_jurisdiction_inconsistent_count = sum(!authority_jurisdiction_consistent, na.rm = TRUE),
      authority_jurisdiction_rate = round(authority_jurisdiction_consistent_count / 
                                        (authority_jurisdiction_consistent_count + authority_jurisdiction_inconsistent_count) * 100, 2),
      
      # Category-type consistency
      category_type_consistent_count = sum(category_type_consistent, na.rm = TRUE),
      category_type_inconsistent_count = sum(!category_type_consistent, na.rm = TRUE),
      category_type_rate = round(category_type_consistent_count / 
                                (category_type_consistent_count + category_type_inconsistent_count) * 100, 2),
      
      # Text completeness
      meaningful_text_count = sum(has_meaningful_text, na.rm = TRUE),
      meaningful_text_rate = round(meaningful_text_count / total_records * 100, 2),
      
      # Overall consistency score
      avg_consistency_rate = round(mean(c(date_consistency_rate, authority_jurisdiction_rate, 
                                         category_type_rate, meaningful_text_rate), na.rm = TRUE), 2)
    )
  
  # Identify inconsistent records
  inconsistent_records <- consistency_checks %>%
    filter(
      !date_urn_consistent | 
      !authority_jurisdiction_consistent | 
      !category_type_consistent |
      !has_meaningful_text
    ) %>%
    select(titulo, urn, autoridade, jurisdicao, categoria, tipo, data,
           date_urn_consistent, authority_jurisdiction_consistent, 
           category_type_consistent, has_meaningful_text) %>%
    slice_head(n = 50)
  
  log_info("Metadata consistency check completed: {consistency_summary$avg_consistency_rate}% average consistency")
  
  return(list(
    summary = consistency_summary,
    detailed_checks = consistency_checks,
    inconsistent_records = inconsistent_records
  ))
}

#' Identify and flag orphaned records or broken relationships
#' @param data Legislative dataset
#' @return Orphaned records analysis
identify_orphaned_records <- function(data) {
  
  log_info("Identifying orphaned records and broken relationships...")
  
  orphaned_analysis <- data %>%
    mutate(
      # Records with minimal information
      has_title = !is.na(titulo) & nchar(titulo) > 5,
      has_urn = !is.na(urn) & nchar(urn) > 10,
      has_authority = !is.na(autoridade) & autoridade != "",
      has_date = !is.na(data),
      has_category = !is.na(categoria) & categoria != "",
      
      # Count of available fields
      field_count = as.numeric(has_title) + as.numeric(has_urn) + 
                   as.numeric(has_authority) + as.numeric(has_date) + 
                   as.numeric(has_category),
      
      # Orphaned record indicators
      minimal_record = field_count <= 2,
      no_text_content = is.na(titulo) & is.na(assuntos) & is.na(ementa),
      no_identification = is.na(urn) & is.na(autoridade),
      
      # Broken relationship indicators
      dangling_reference = !is.na(urn) & str_detect(tolower(coalesce(titulo, "")), "altera|revoga|regulamenta") & 
                          !any(str_detect(data$urn, str_extract(urn, "\\d+"))),
      
      # Overall orphaned status
      is_orphaned = minimal_record | no_text_content | no_identification
    )
  
  # Orphaned records summary
  orphaned_summary <- orphaned_analysis %>%
    summarise(
      total_records = n(),
      minimal_records = sum(minimal_record, na.rm = TRUE),
      no_text_records = sum(no_text_content, na.rm = TRUE),
      no_id_records = sum(no_identification, na.rm = TRUE),
      dangling_refs = sum(dangling_reference, na.rm = TRUE),
      total_orphaned = sum(is_orphaned, na.rm = TRUE),
      orphaned_rate = round(total_orphaned / total_records * 100, 2)
    )
  
  # Get actual orphaned records
  orphaned_records <- orphaned_analysis %>%
    filter(is_orphaned) %>%
    select(titulo, urn, autoridade, data, categoria, field_count, 
           minimal_record, no_text_content, no_identification) %>%
    arrange(field_count) %>%
    slice_head(n = 100)
  
  log_info("Orphaned records analysis: {orphaned_summary$total_orphaned} orphaned ({orphaned_summary$orphaned_rate}%)")
  
  return(list(
    summary = orphaned_summary,
    orphaned_records = orphaned_records,
    detailed_analysis = orphaned_analysis
  ))
}

#' Implement automated data lineage tracking
#' @param data Legislative dataset
#' @return Data lineage tracking information
implement_data_lineage <- function(data) {
  
  log_info("Implementing data lineage tracking...")
  
  # Create data lineage metadata
  lineage_info <- list(
    # Dataset fingerprint
    dataset_hash = digest(data, algo = "md5"),
    record_count = nrow(data),
    column_count = ncol(data),
    creation_timestamp = Sys.time(),
    
    # Data source tracking
    source_files = unique(data$source_file[!is.na(data$source_file)]),
    data_collection_dates = range(as.Date(data$data_coleta), na.rm = TRUE),
    content_date_range = range(as.Date(data$data), na.rm = TRUE),
    
    # Data quality fingerprints
    completeness_fingerprint = data %>%
      summarise_all(~round(sum(!is.na(.) & . != "") / n() * 100, 1)) %>%
      digest(algo = "md5"),
    
    # Key field distributions
    authority_distribution = table(data$autoridade, useNA = "ifany"),
    category_distribution = table(data$categoria, useNA = "ifany"),
    jurisdiction_distribution = table(data$jurisdicao, useNA = "ifany"),
    
    # Data transformation history
    transformation_log = list(
      list(
        step = "initial_load",
        timestamp = Sys.time(),
        description = "Initial data loading and preparation",
        record_count = nrow(data)
      )
    )
  )
  
  # Create lineage tracking functions
  lineage_functions <- list(
    add_transformation = function(step_name, description, new_data = NULL) {
      new_entry <- list(
        step = step_name,
        timestamp = Sys.time(),
        description = description,
        record_count = if(!is.null(new_data)) nrow(new_data) else NA,
        data_hash = if(!is.null(new_data)) digest(new_data, algo = "md5") else NA
      )
      lineage_info$transformation_log <<- append(lineage_info$transformation_log, list(new_entry))
      return(lineage_info)
    },
    
    get_lineage_summary = function() {
      tibble(
        step = map_chr(lineage_info$transformation_log, "step"),
        timestamp = map_chr(lineage_info$transformation_log, "timestamp"),
        description = map_chr(lineage_info$transformation_log, "description"),
        record_count = map_dbl(lineage_info$transformation_log, "record_count")
      )
    }
  )
  
  log_info("Data lineage tracking implemented with {length(lineage_info$source_files)} source files")
  
  return(list(
    lineage_info = lineage_info,
    lineage_functions = lineage_functions
  ))
}

#' Validate analytical methods and results
#' @param analytical_results List of results from different analytical methods
#' @return Analytical validation results
validate_analytical_methods <- function(analytical_results = NULL) {
  
  log_info("Validating analytical methods...")
  
  validation_results <- list()
  
  # 1. Topic model stability validation
  if (!is.null(analytical_results$topic_models)) {
    topic_validation <- validate_topic_models(analytical_results$topic_models)
    validation_results$topic_models <- topic_validation
  }
  
  # 2. Sentiment analysis validation
  if (!is.null(analytical_results$sentiment)) {
    sentiment_validation <- validate_sentiment_analysis(analytical_results$sentiment)
    validation_results$sentiment_analysis <- sentiment_validation
  }
  
  # 3. Network analysis validation
  if (!is.null(analytical_results$network)) {
    network_validation <- validate_network_analysis(analytical_results$network)
    validation_results$network_analysis <- network_validation
  }
  
  # 4. Temporal analysis validation
  if (!is.null(analytical_results$temporal)) {
    temporal_validation <- validate_temporal_analysis(analytical_results$temporal)
    validation_results$temporal_analysis <- temporal_validation
  }
  
  # Overall validation summary
  validation_summary <- list(
    total_methods_validated = length(validation_results),
    validation_timestamp = Sys.time(),
    overall_quality_score = if(length(validation_results) > 0) {
      mean(map_dbl(validation_results, "quality_score"), na.rm = TRUE)
    } else NA
  )
  
  log_info("Analytical validation completed for {validation_summary$total_methods_validated} methods")
  
  return(list(
    validation_results = validation_results,
    validation_summary = validation_summary
  ))
}

#' Validate topic model stability
#' @param topic_models Topic modeling results
#' @return Topic model validation results
validate_topic_models <- function(topic_models) {
  
  if (is.null(topic_models$LDA)) {
    return(list(quality_score = NA, issues = "No LDA models found"))
  }
  
  # Check model coherence and perplexity
  lda_models <- topic_models$LDA
  perplexity_scores <- map_dbl(lda_models, ~ tryCatch(perplexity(.x), error = function(e) NA))
  
  validation <- list(
    num_models = length(lda_models),
    perplexity_range = range(perplexity_scores, na.rm = TRUE),
    avg_perplexity = mean(perplexity_scores, na.rm = TRUE),
    perplexity_stability = sd(perplexity_scores, na.rm = TRUE) / mean(perplexity_scores, na.rm = TRUE),
    
    # Quality assessment
    quality_score = case_when(
      length(lda_models) >= 3 ~ 0.8,
      length(lda_models) >= 2 ~ 0.6,
      TRUE ~ 0.4
    ),
    
    issues = if(any(is.na(perplexity_scores))) "Some models failed perplexity calculation" else "None"
  )
  
  return(validation)
}

#' Validate sentiment analysis results
#' @param sentiment_results Sentiment analysis results
#' @return Sentiment validation results
validate_sentiment_analysis <- function(sentiment_results) {
  
  if (is.null(sentiment_results)) {
    return(list(quality_score = NA, issues = "No sentiment results found"))
  }
  
  validation <- list(
    # Check sentiment distribution
    sentiment_distribution = table(sentiment_results$sentiment_category, useNA = "ifany"),
    
    # Check for extreme values
    extreme_positive = sum(sentiment_results$sentiment_score > 2, na.rm = TRUE),
    extreme_negative = sum(sentiment_results$sentiment_score < -2, na.rm = TRUE),
    
    # Balance check
    sentiment_balance = abs(mean(sentiment_results$sentiment_score, na.rm = TRUE)),
    
    # Quality score
    quality_score = case_when(
      all(!is.na(sentiment_results$sentiment_score)) ~ 0.9,
      sum(is.na(sentiment_results$sentiment_score)) / length(sentiment_results$sentiment_score) < 0.1 ~ 0.7,
      TRUE ~ 0.5
    ),
    
    issues = if(sum(is.na(sentiment_results$sentiment_score)) > 0) "Missing sentiment scores detected" else "None"
  )
  
  return(validation)
}

#' Validate network analysis results
#' @param network_results Network analysis results
#' @return Network validation results
validate_network_analysis <- function(network_results) {
  
  if (is.null(network_results$graph)) {
    return(list(quality_score = NA, issues = "No network graph found"))
  }
  
  graph <- network_results$graph
  
  validation <- list(
    node_count = igraph::vcount(graph),
    edge_count = igraph::ecount(graph),
    density = igraph::edge_density(graph),
    is_connected = igraph::is_connected(graph),
    components = igraph::components(graph)$no,
    
    # Quality assessment
    quality_score = case_when(
      igraph::vcount(graph) > 100 & igraph::ecount(graph) > 50 ~ 0.9,
      igraph::vcount(graph) > 50 & igraph::ecount(graph) > 20 ~ 0.7,
      TRUE ~ 0.5
    ),
    
    issues = if(igraph::components(graph)$no > 10) "Network is highly fragmented" else "None"
  )
  
  return(validation)
}

#' Validate temporal analysis results
#' @param temporal_results Temporal analysis results
#' @return Temporal validation results
validate_temporal_analysis <- function(temporal_results) {
  
  if (is.null(temporal_results$time_series)) {
    return(list(quality_score = NA, issues = "No time series data found"))
  }
  
  ts_data <- temporal_results$time_series
  
  validation <- list(
    time_span_years = as.numeric(difftime(max(ts_data$year_month), min(ts_data$year_month), units = "days")) / 365.25,
    observation_count = nrow(ts_data),
    missing_periods = sum(ts_data$count == 0),
    
    # Quality score
    quality_score = case_when(
      nrow(ts_data) > 100 ~ 0.9,
      nrow(ts_data) > 50 ~ 0.7,
      TRUE ~ 0.5
    ),
    
    issues = if(sum(ts_data$count == 0) / nrow(ts_data) > 0.5) "Many periods with zero observations" else "None"
  )
  
  return(validation)
}

#' Generate comprehensive data integrity report
#' @param integrity_results All integrity check results
#' @param output_dir Output directory
generate_integrity_report <- function(integrity_results, output_dir) {
  
  log_info("Generating comprehensive data integrity report...")
  
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Create summary dashboard data
  summary_metrics <- list(
    urn_compliance = integrity_results$urn_validation$summary$full_compliance_rate,
    metadata_consistency = integrity_results$metadata_consistency$summary$avg_consistency_rate,
    orphaned_rate = integrity_results$orphaned_records$summary$orphaned_rate,
    overall_integrity_score = mean(c(
      integrity_results$urn_validation$summary$full_compliance_rate,
      integrity_results$metadata_consistency$summary$avg_consistency_rate,
      100 - integrity_results$orphaned_records$summary$orphaned_rate
    ), na.rm = TRUE)
  )
  
  # Data quality visualization
  quality_plot <- tibble(
    metric = c("URN Compliance", "Metadata Consistency", "Record Completeness"),
    score = c(
      summary_metrics$urn_compliance,
      summary_metrics$metadata_consistency,
      100 - summary_metrics$orphaned_rate
    )
  ) %>%
    ggplot(aes(x = reorder(metric, score), y = score)) +
    geom_col(fill = "steelblue") +
    geom_text(aes(label = paste0(round(score, 1), "%")), hjust = -0.1) +
    coord_flip() +
    ylim(0, 100) +
    labs(title = "Data Integrity Quality Metrics",
         x = "Metric", y = "Score (%)") +
    theme_minimal()
  
  ggsave(file.path(output_dir, "data_integrity_metrics.png"), quality_plot,
         width = 10, height = 6, dpi = 300)
  
  # Save detailed results
  saveRDS(integrity_results, file.path(output_dir, "integrity_analysis_results.rds"))
  write_csv(integrity_results$urn_validation$problematic_urns, 
            file.path(output_dir, "problematic_urns.csv"))
  write_csv(integrity_results$metadata_consistency$inconsistent_records, 
            file.path(output_dir, "inconsistent_metadata.csv"))
  write_csv(integrity_results$orphaned_records$orphaned_records, 
            file.path(output_dir, "orphaned_records.csv"))
  
  # Generate executive summary
  summary_text <- glue::glue("
    DATA INTEGRITY ANALYSIS SUMMARY
    ===============================
    
    Overall Integrity Score: {round(summary_metrics$overall_integrity_score, 1)}%
    
    URN Compliance: {round(summary_metrics$urn_compliance, 1)}%
    Metadata Consistency: {round(summary_metrics$metadata_consistency, 1)}%
    Record Completeness: {round(100 - summary_metrics$orphaned_rate, 1)}%
    
    Total Records Analyzed: {integrity_results$urn_validation$summary$total_records}
    Problematic URNs: {nrow(integrity_results$urn_validation$problematic_urns)}
    Inconsistent Metadata: {nrow(integrity_results$metadata_consistency$inconsistent_records)}
    Orphaned Records: {integrity_results$orphaned_records$summary$total_orphaned}
  ")
  
  writeLines(summary_text, file.path(output_dir, "integrity_summary.txt"))
  
  log_info("Data integrity report generated: {round(summary_metrics$overall_integrity_score, 1)}% overall integrity score")
  
  return(summary_metrics)
}

#' Main data integrity validation pipeline
#' @param data_source Path to data file or data frame
#' @param output_dir Output directory for results
#' @param analytical_results Optional analytical results for validation
run_integrity_validation <- function(data_source, output_dir, analytical_results = NULL) {
  
  log_info("=== STARTING DATA INTEGRITY VALIDATION ===")
  
  # Load data
  if (is.character(data_source)) {
    data <- read_parquet(data_source)
  } else {
    data <- data_source
  }
  
  # 1. URN format validation
  urn_validation <- validate_urn_compliance(data)
  
  # 2. Metadata consistency checks
  metadata_consistency <- check_metadata_consistency(data)
  
  # 3. Orphaned records identification
  orphaned_records <- identify_orphaned_records(data)
  
  # 4. Data lineage implementation
  data_lineage <- implement_data_lineage(data)
  
  # 5. Analytical method validation
  analytical_validation <- validate_analytical_methods(analytical_results)
  
  # Combine all results
  integrity_results <- list(
    urn_validation = urn_validation,
    metadata_consistency = metadata_consistency,
    orphaned_records = orphaned_records,
    data_lineage = data_lineage,
    analytical_validation = analytical_validation
  )
  
  # 6. Generate comprehensive report
  summary_metrics <- generate_integrity_report(integrity_results, output_dir)
  
  log_info("=== DATA INTEGRITY VALIDATION COMPLETED ===")
  log_info("Overall integrity score: {round(summary_metrics$overall_integrity_score, 1)}%")
  
  return(integrity_results)
}

# Execute if run as script
if (!interactive()) {
  # Set paths
  parquet_file <- "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/parquet_dataset/combined_legislative_dataset.parquet"
  output_dir <- file.path(dirname(dirname(parquet_file)), "integrity_validation_results")
  
  # Check if Parquet file exists
  if (!file.exists(parquet_file)) {
    cat("Parquet file not found. Please run CSV to Parquet conversion first.\n")
    quit(status = 1)
  }
  
  # Run integrity validation
  results <- run_integrity_validation(parquet_file, output_dir)
  
  cat("Data integrity validation completed. Results saved to:", output_dir, "\n")
}