# ============================================================================
# INTEGRATED TEXT ANALYTICS SYSTEM
# Brazilian Legislative Monitoring System - Complete NLP Integration
# Author: Legislative Data Science Framework
# Date: 2025-09-01
# Description: Complete integration of all enhanced text analytics components
#              for Brazilian legislative document analysis at scale
# ============================================================================

# Load all NLP system components
cat("🚀 Loading Enhanced Text Analytics System Components...\n")

source("src/enhanced_brazilian_legal_nlp_system.R")
source("src/advanced_topic_modeling_sentiment.R")
source("src/interactive_text_exploration_research.R")
source("src/enhanced_text_analytics_dashboard.R")
source("src/performance_optimization_nlp.R")

# System Integration Functions ==========================================

#' Initialize Complete Text Analytics System
#' 
#' Comprehensive initialization of all text analytics components with
#' performance optimization, data loading, and system configuration
#' 
#' @param data_source Data source type: "csv", "database", "sample"
#' @param sample_size Sample size for analysis (if using sample data)
#' @param enable_performance Enable performance optimization
#' @return Initialized system handle
initialize_text_analytics_system <- function(data_source = "csv",
                                            sample_size = 10000,
                                            enable_performance = TRUE) {
  
  start_time <- Sys.time()
  cat("🎯 Initializing Complete Text Analytics System\n")
  cat("=" %+% strrep("=", 50) %+% "\n")
  
  # Initialize system components
  system_handle <- list(
    data = NULL,
    performance_handle = NULL,
    processing_results = list(),
    system_config = list(
      data_source = data_source,
      sample_size = sample_size,
      enable_performance = enable_performance,
      initialized_at = Sys.time()
    )
  )
  
  # Step 1: Performance optimization setup
  if (enable_performance) {
    cat("⚡ Step 1: Initializing performance optimization...\n")
    system_handle$performance_handle <- initialize_performance_system()
  }
  
  # Step 2: Data loading
  cat("📊 Step 2: Loading legislative data...\n")
  system_handle$data <- load_legislative_data(
    source = data_source,
    sample_size = sample_size
  )
  
  cat("✅ Loaded", nrow(system_handle$data), "documents\n")
  
  # Step 3: System validation
  cat("🔍 Step 3: Validating system components...\n")
  validation_results <- validate_system_components(system_handle)
  
  if (!validation_results$all_valid) {
    stop("❌ System validation failed: ", paste(validation_results$errors, collapse = ", "))
  }
  
  initialization_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  cat("🎉 Text Analytics System initialized successfully!\n")
  cat("⏱️ Initialization time:", round(initialization_time, 2), "minutes\n\n")
  
  return(system_handle)
}

#' Run Complete Text Analytics Pipeline
#' 
#' Execute comprehensive text analytics pipeline with all components
#' including preprocessing, entity recognition, sentiment analysis,
#' topic modeling, and interactive exploration
#' 
#' @param system_handle Initialized system handle
#' @param analysis_components Components to run
#' @param output_format Output format for results
#' @return Complete analysis results
run_complete_text_analytics_pipeline <- function(system_handle,
                                                 analysis_components = c("all"),
                                                 output_format = "comprehensive") {
  
  start_time <- Sys.time()
  cat("🚀 Running Complete Text Analytics Pipeline\n")
  cat("=" %+% strrep("=", 50) %+% "\n")
  
  # Prepare texts and metadata
  texts <- system_handle$data$combined_text
  metadata <- system_handle$data[, !names(system_handle$data) %in% "combined_text"]
  
  # Initialize results structure
  pipeline_results <- list(
    preprocessing = NULL,
    entity_recognition = NULL,
    sentiment_analysis = NULL,
    topic_modeling = NULL,
    text_similarity = NULL,
    kwic_analysis = NULL,
    research_report = NULL,
    performance_metrics = list(),
    system_metadata = list()
  )
  
  # Determine which components to run
  if ("all" %in% analysis_components) {
    components_to_run <- c("preprocessing", "entities", "sentiment", "topics", "similarity", "kwic")
  } else {
    components_to_run <- analysis_components
  }
  
  cat("🎯 Running components:", paste(components_to_run, collapse = ", "), "\n\n")
  
  # Component 1: Enhanced Text Preprocessing
  if ("preprocessing" %in% components_to_run) {
    cat("🔧 Component 1: Enhanced Text Preprocessing\n")
    
    if (!is.null(system_handle$performance_handle)) {
      pipeline_results$preprocessing <- optimized_large_scale_preprocessing(
        texts = texts,
        performance_handle = system_handle$performance_handle
      )
      texts <- pipeline_results$preprocessing$texts
    } else {
      pipeline_results$preprocessing <- preprocess_legal_corpus(texts)
      texts <- pipeline_results$preprocessing$texts
    }
    
    cat("✅ Preprocessing completed:", length(texts), "documents processed\n\n")
  }
  
  # Component 2: Brazilian Legal Entity Recognition  
  if ("entities" %in% components_to_run) {
    cat("🏛️ Component 2: Brazilian Legal Entity Recognition\n")
    
    if (!is.null(system_handle$performance_handle)) {
      pipeline_results$entity_recognition <- memory_efficient_entity_recognition(
        texts = texts,
        performance_handle = system_handle$performance_handle
      )
    } else {
      pipeline_results$entity_recognition <- extract_brazilian_legal_entities(texts)
    }
    
    total_entities <- sum(sapply(pipeline_results$entity_recognition[1:5], nrow))
    cat("✅ Entity recognition completed:", total_entities, "unique entities found\n\n")
  }
  
  # Component 3: Advanced Regulatory Sentiment Analysis
  if ("sentiment" %in% components_to_run) {
    cat("😊 Component 3: Advanced Regulatory Sentiment Analysis\n")
    
    pipeline_results$sentiment_analysis <- advanced_regulatory_sentiment_analysis(
      texts = texts,
      metadata = metadata,
      method = "hybrid"
    )
    
    avg_sentiment <- mean(pipeline_results$sentiment_analysis$sentiment_scores$compound_sentiment, na.rm = TRUE)
    cat("✅ Sentiment analysis completed: Average sentiment =", round(avg_sentiment, 3), "\n\n")
  }
  
  # Component 4: Advanced Topic Modeling
  if ("topics" %in% components_to_run) {
    cat("📚 Component 4: Advanced Topic Modeling\n")
    
    if (!is.null(system_handle$performance_handle)) {
      pipeline_results$topic_modeling <- high_performance_topic_modeling(
        texts = texts,
        performance_handle = system_handle$performance_handle
      )
    } else {
      pipeline_results$topic_modeling <- advanced_legal_topic_modeling(
        texts = texts,
        metadata = metadata,
        methods = c("lda", "stm")
      )
    }
    
    optimal_topics <- ifelse(!is.null(pipeline_results$topic_modeling$optimal_k),
                           pipeline_results$topic_modeling$optimal_k,
                           pipeline_results$topic_modeling$best_model$optimal_k)
    cat("✅ Topic modeling completed:", optimal_topics, "optimal topics identified\n\n")
  }
  
  # Component 5: Comprehensive Text Similarity Analysis
  if ("similarity" %in% components_to_run) {
    cat("🔗 Component 5: Comprehensive Text Similarity Analysis\n")
    
    # Sample for similarity analysis if corpus is very large
    similarity_texts <- if (length(texts) > 5000) texts[1:5000] else texts
    similarity_metadata <- if (length(texts) > 5000) metadata[1:5000, ] else metadata
    
    pipeline_results$text_similarity <- comprehensive_text_similarity_analysis(
      texts = similarity_texts,
      metadata = similarity_metadata,
      similarity_methods = c("cosine", "jaccard"),
      clustering_methods = c("hierarchical", "kmeans"),
      interactive = FALSE  # Set to FALSE for pipeline mode
    )
    
    cat("✅ Text similarity analysis completed\n\n")
  }
  
  # Component 6: Advanced KWIC Analysis
  if ("kwic" %in% components_to_run) {
    cat("🔍 Component 6: Advanced KWIC Analysis\n")
    
    # Auto-detect keywords or use predefined set
    transport_keywords <- c(
      "transporte", "logística", "rodoviário", "caminhão", "frete",
      "combustível", "biodiesel", "sustentável", "emissão", "regulamentação"
    )
    
    pipeline_results$kwic_analysis <- advanced_kwic_analysis(
      texts = texts,
      keywords = transport_keywords,
      window_size = 10,
      metadata = metadata
    )
    
    total_kwic <- sum(sapply(pipeline_results$kwic_analysis$keyword_contexts, nrow))
    cat("✅ KWIC analysis completed:", total_kwic, "keyword contexts identified\n\n")
  }
  
  # Component 7: Generate Academic Research Report
  if ("research" %in% components_to_run || output_format == "research_report") {
    cat("📄 Component 7: Generating Academic Research Report\n")
    
    pipeline_results$research_report <- generate_academic_research_report(
      nlp_results = pipeline_results,
      metadata = metadata,
      output_format = "pdf",
      citation_style = "abnt"
    )
    
    cat("✅ Academic research report generated\n\n")
  }
  
  # Performance metrics collection
  total_processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  
  pipeline_results$performance_metrics <- list(
    total_processing_time_minutes = total_processing_time,
    documents_processed = length(texts),
    components_executed = components_to_run,
    processing_speed_docs_per_minute = length(texts) / total_processing_time,
    memory_usage = if (requireNamespace("pryr", quietly = TRUE)) pryr::mem_used() else NA,
    system_info = Sys.info()
  )
  
  # System metadata
  pipeline_results$system_metadata <- list(
    execution_timestamp = Sys.time(),
    system_configuration = system_handle$system_config,
    r_version = R.version.string,
    platform = Sys.info()["sysname"],
    enhanced_features_used = components_to_run
  )
  
  cat("🎉 Complete Text Analytics Pipeline finished successfully!\n")
  cat("📊 Processed", length(texts), "documents in", round(total_processing_time, 2), "minutes\n")
  cat("⚡ Processing speed:", round(length(texts) / total_processing_time, 1), "documents/minute\n\n")
  
  return(pipeline_results)
}

#' Create Text Analytics Dashboard Application
#' 
#' Launch the complete interactive dashboard with all enhanced features
#' 
#' @param system_handle Initialized system handle
#' @param port Port for dashboard application
#' @param launch_browser Launch browser automatically
#' @return Shiny application object
create_text_analytics_app <- function(system_handle, 
                                     port = 8080,
                                     launch_browser = TRUE) {
  
  cat("🎨 Creating Enhanced Text Analytics Dashboard Application\n")
  
  # Create Shiny UI
  ui <- create_enhanced_text_analytics_dashboard()
  
  # Create Shiny Server
  server <- function(input, output, session) {
    
    # Initialize server logic with system handle
    server_logic <- create_enhanced_text_analytics_server(input, output, session)
    
    # Pass system data to server
    server_logic$system_data <- system_handle$data
    server_logic$performance_handle <- system_handle$performance_handle
    
    return(server_logic)
  }
  
  # Create Shiny app
  app <- shinyApp(ui = ui, server = server)
  
  cat("✅ Dashboard application created successfully!\n")
  cat("🌐 Ready to launch on port", port, "\n")
  
  if (launch_browser) {
    cat("🚀 Launching dashboard...\n")
    runApp(app, port = port, launch.browser = TRUE)
  }
  
  return(app)
}

# Data Loading Functions ===============================================

#' Load Legislative Data from Various Sources
#' 
#' @param source Data source type
#' @param sample_size Sample size if using sample data
#' @return Loaded legislative data
load_legislative_data <- function(source = "csv", sample_size = 10000) {
  
  cat("📊 Loading legislative data from source:", source, "\n")
  
  if (source == "csv") {
    # Try to load from the main CSV file
    csv_files <- list.files(
      path = "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4",
      pattern = "*.csv",
      full.names = TRUE
    )
    
    # Look for the main dataset
    main_csv <- csv_files[str_detect(csv_files, "railway_data_50k|railway_medium_dataset")]
    
    if (length(main_csv) > 0) {
      cat("📄 Loading from CSV file:", basename(main_csv[1]), "\n")
      data <- read_csv(main_csv[1], locale = locale(encoding = "UTF-8"))
      
      # Create combined text if not already present
      if (!"combined_text" %in% names(data)) {
        data <- data %>%
          mutate(combined_text = paste(
            ifelse(is.na(titulo), "", titulo),
            ifelse(is.na(ementa), "", ementa),
            ifelse(is.na(assuntos), "", assuntos),
            sep = " "
          ))
      }
      
      # Sample if requested
      if (nrow(data) > sample_size) {
        data <- data %>% sample_n(sample_size)
      }
      
      return(data)
    }
  }
  
  # Fallback to sample data
  cat("🎲 Generating sample legislative data...\n")
  return(generate_sample_legislative_data(sample_size))
}

#' Generate Sample Legislative Data
generate_sample_legislative_data <- function(n_docs = 10000) {
  
  # Sample legal document types and themes
  document_types <- c("Lei", "Decreto", "Resolução", "Portaria", "Instrução Normativa")
  jurisdictions <- c("Federal", "SP", "RJ", "MG", "RS", "PR", "SC", "BA")
  categories <- c("Legislação", "Jurisprudência", "Doutrina")
  
  # Transport-related terms for realistic content
  transport_terms <- c(
    "transporte rodoviário", "logística", "combustível", "biodiesel",
    "caminhão", "frete", "infraestrutura", "sustentabilidade",
    "emissão", "regulamentação", "fiscalização", "licenciamento"
  )
  
  tibble(
    titulo = paste(
      sample(document_types, n_docs, replace = TRUE),
      "nº",
      sample(1000:9999, n_docs, replace = TRUE),
      "de",
      format(sample(seq(as.Date("1990-01-01"), as.Date("2024-12-31"), by = "day"), n_docs), "%d/%m/%Y")
    ),
    
    ementa = map_chr(1:n_docs, ~ {
      terms <- sample(transport_terms, sample(2:4, 1))
      paste("Regulamenta questões relacionadas a", paste(terms, collapse = " e "), 
            "no âmbito do sistema de transporte brasileiro.")
    }),
    
    assuntos = map_chr(1:n_docs, ~ {
      paste(sample(transport_terms, sample(2:3, 1)), collapse = ", ")
    }),
    
    categoria = sample(categories, n_docs, replace = TRUE),
    jurisdicao = sample(jurisdictions, n_docs, replace = TRUE),
    ano = sample(1990:2024, n_docs, replace = TRUE),
    
    combined_text = paste(titulo, ementa, assuntos, sep = " ")
  )
}

#' Validate System Components
validate_system_components <- function(system_handle) {
  
  validation_results <- list(
    all_valid = TRUE,
    errors = c(),
    warnings = c()
  )
  
  # Check data
  if (is.null(system_handle$data) || nrow(system_handle$data) == 0) {
    validation_results$all_valid <- FALSE
    validation_results$errors <- c(validation_results$errors, "No data loaded")
  }
  
  # Check required columns
  required_columns <- c("combined_text")
  missing_columns <- required_columns[!required_columns %in% names(system_handle$data)]
  if (length(missing_columns) > 0) {
    validation_results$all_valid <- FALSE
    validation_results$errors <- c(validation_results$errors, 
                                  paste("Missing columns:", paste(missing_columns, collapse = ", ")))
  }
  
  # Check performance handle
  if (system_handle$system_config$enable_performance && is.null(system_handle$performance_handle)) {
    validation_results$warnings <- c(validation_results$warnings, "Performance optimization not initialized")
  }
  
  return(validation_results)
}

# Export Functions =====================================================

#' Export Analysis Results to Various Formats
#' 
#' @param results Analysis results to export
#' @param format Export format
#' @param filename Output filename
export_analysis_results <- function(results, format = "excel", filename = NULL) {
  
  if (is.null(filename)) {
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("text_analytics_results_", timestamp)
  }
  
  cat("💾 Exporting analysis results to", format, "format...\n")
  
  if (format == "excel") {
    # Export to Excel with multiple sheets
    export_to_excel(results, filename)
  } else if (format == "pdf") {
    # Export summary report to PDF
    export_to_pdf(results, filename)
  } else if (format == "json") {
    # Export to JSON
    export_to_json(results, filename)
  }
  
  cat("✅ Results exported to:", filename, "\n")
}

# System Status Functions ==============================================

#' Get System Status
get_system_status <- function(system_handle) {
  list(
    status = "operational",
    uptime = difftime(Sys.time(), system_handle$system_config$initialized_at, units = "hours"),
    documents_loaded = nrow(system_handle$data),
    memory_usage = if (requireNamespace("pryr", quietly = TRUE)) pryr::mem_used() else NA,
    performance_enabled = !is.null(system_handle$performance_handle),
    last_analysis = system_handle$processing_results$system_metadata$execution_timestamp %||% "None"
  )
}

# Main Execution Functions =============================================

#' Quick Start Text Analytics
#' 
#' One-function setup and execution of the complete text analytics system
#' 
#' @param sample_size Number of documents to analyze
#' @param launch_dashboard Launch interactive dashboard
#' @param components Components to run
#' @return Complete system results
quick_start_text_analytics <- function(sample_size = 5000,
                                      launch_dashboard = FALSE,
                                      components = c("all")) {
  
  cat("🚀 Quick Start: Enhanced Text Analytics for Brazilian Legislative Documents\n")
  cat("=" %+% strrep("=", 70) %+% "\n\n")
  
  # Initialize system
  system_handle <- initialize_text_analytics_system(
    data_source = "csv",
    sample_size = sample_size,
    enable_performance = TRUE
  )
  
  # Run analysis pipeline
  results <- run_complete_text_analytics_pipeline(
    system_handle = system_handle,
    analysis_components = components,
    output_format = "comprehensive"
  )
  
  # Store results in system handle
  system_handle$processing_results <- results
  
  # Launch dashboard if requested
  if (launch_dashboard) {
    cat("🎨 Launching interactive dashboard...\n")
    create_text_analytics_app(system_handle, launch_browser = TRUE)
  }
  
  return(list(
    system_handle = system_handle,
    analysis_results = results,
    status = get_system_status(system_handle)
  ))
}

# Final System Export
cat("🎉 Integrated Text Analytics System loaded successfully!\n")
cat("🔧 Available main functions:\n")
cat("   - initialize_text_analytics_system(): Initialize complete system\n")
cat("   - run_complete_text_analytics_pipeline(): Execute full analysis pipeline\n") 
cat("   - create_text_analytics_app(): Launch interactive dashboard\n")
cat("   - quick_start_text_analytics(): One-command system startup\n")
cat("\n📚 Enhanced Brazilian Legal Text Analytics System Ready!\n")
cat("🎯 Specialized for Portuguese legal language processing\n")
cat("⚡ Optimized for 134k+ document corpus analysis\n")
cat("🔬 Academic research standards with statistical validation\n")
cat("🌐 Interactive dashboard with government decision-support features\n")
cat("\n💡 To get started quickly, run: quick_start_text_analytics()\n")