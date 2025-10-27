# ============================================================================
# INTERACTIVE TEXT EXPLORATION AND ACADEMIC RESEARCH FEATURES
# Brazilian Legislative Monitoring System - Enhanced Text Analytics (Part 3)
# Author: Legislative Data Science Framework
# Date: 2025-09-01
# Description: Interactive text exploration tools and academic research features
#              with publication-ready reports and statistical testing
# ============================================================================

# Source previous components
source("src/enhanced_brazilian_legal_nlp_system.R")
source("src/advanced_topic_modeling_sentiment.R")

# Additional libraries for interactive exploration and research
suppressPackageStartupMessages({
  library(shinyWidgets)   # Enhanced Shiny widgets
  library(reactable)      # Interactive tables
  library(crosstalk)      # Widget interactivity
  library(htmlwidgets)    # HTML widgets
  library(leaflet)        # Interactive maps
  library(timevis)        # Timeline visualizations
  library(collapsibleTree) # Hierarchical trees
  library(sunburstR)      # Sunburst plots
  library(treemap)        # Treemap visualizations
  library(wordcloud2)     # Advanced word clouds
  library(echarts4r)      # Interactive charts
  library(apexcharter)    # Modern charts
  library(highcharter)    # Interactive charts
  library(formattable)    # Table formatting
  library(kableExtra)     # Enhanced tables
  library(gt)             # Grammar of tables
  library(flextable)      # Flexible tables
  library(officer)        # Office document generation
  library(rmarkdown)      # R Markdown reports
  library(bookdown)       # Academic publishing
  library(papaja)         # APA formatted papers
  library(broom)          # Tidy model outputs
  library(broom.mixed)    # Mixed model outputs
  library(effectsize)     # Effect size calculations
  library(parameters)     # Model parameters
  library(performance)    # Model performance
  library(see)            # Visualization
  library(bayestestR)     # Bayesian statistics
  library(rstanarm)       # Bayesian regression
  library(brms)           # Bayesian models
  library(survival)       # Survival analysis
  library(survminer)      # Survival visualization
  library(psych)          # Psychological research
  library(corrr)          # Tidy correlations
  library(factoextra)     # Factor analysis
  library(FactoMineR)     # Multivariate analysis
  library(cluster)        # Cluster analysis
  library(dendextend)     # Dendrogram extensions
  library(fpc)            # Clustering validation
  library(NbClust)        # Optimal cluster number
})

# Interactive Text Exploration System =======================================

#' Comprehensive Text Similarity and Document Clustering Analysis
#' 
#' Advanced document similarity analysis with multiple similarity measures,
#' hierarchical clustering, and interactive exploration capabilities
#' 
#' @param texts Vector of preprocessed texts
#' @param metadata Document metadata
#' @param similarity_methods Vector of similarity methods to compute
#' @param clustering_methods Vector of clustering methods to apply
#' @param interactive Generate interactive visualizations
#' @return Comprehensive similarity and clustering results
comprehensive_text_similarity_analysis <- function(texts,
                                                  metadata = NULL, 
                                                  similarity_methods = c("cosine", "jaccard", "semantic"),
                                                  clustering_methods = c("hierarchical", "kmeans", "dbscan"),
                                                  interactive = TRUE) {
  
  start_time <- Sys.time()
  cat("🔗 Comprehensive Text Similarity and Clustering Analysis\n")
  cat("📊 Processing", length(texts), "documents\n")
  cat("🎯 Computing", length(similarity_methods), "similarity measures\n")
  
  # Initialize results structure
  similarity_results <- list(
    similarity_matrices = list(),
    clustering_results = list(),
    document_embeddings = NULL,
    similarity_network = NULL,
    interactive_visualizations = list(),
    processing_metadata = list()
  )
  
  # Create document corpus for analysis
  cat("📋 Preparing document corpus for similarity analysis...\n")
  
  corpus_quanteda <- corpus(texts)
  tokens_quanteda <- corpus_quanteda %>%
    tokens(what = "word", remove_punct = TRUE, remove_symbols = TRUE) %>%
    tokens_tolower() %>%
    tokens_remove(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_stopwords) %>%
    tokens_wordstem(language = "pt")
  
  dfm_quanteda <- tokens_quanteda %>%
    dfm() %>%
    dfm_trim(min_docfreq = 2, max_docfreq = 0.98, docfreq_type = "prop")
  
  # Compute TF-IDF matrix
  dfm_tfidf <- dfm_weight(dfm_quanteda, scheme = "tfidf")
  
  # Method 1: Cosine Similarity
  if ("cosine" %in% similarity_methods) {
    cat("🔄 Computing cosine similarity matrix...\n")
    similarity_results$similarity_matrices$cosine <- compute_cosine_similarity_matrix(dfm_tfidf)
  }
  
  # Method 2: Jaccard Similarity  
  if ("jaccard" %in% similarity_methods) {
    cat("🔄 Computing Jaccard similarity matrix...\n")
    similarity_results$similarity_matrices$jaccard <- compute_jaccard_similarity_matrix(dfm_quanteda)
  }
  
  # Method 3: Semantic Similarity (if available)
  if ("semantic" %in% similarity_methods) {
    cat("🔄 Computing semantic similarity matrix...\n")
    similarity_results$similarity_matrices$semantic <- tryCatch({
      compute_semantic_similarity_matrix(texts)
    }, error = function(e) {
      cat("⚠️ Semantic similarity computation failed:", e$message, "\n")
      NULL
    })
  }
  
  # Document clustering using multiple methods
  cat("🎯 Performing document clustering analysis...\n")
  
  # Use the best available similarity matrix for clustering
  primary_similarity <- similarity_results$similarity_matrices[[1]]
  distance_matrix <- 1 - primary_similarity  # Convert similarity to distance
  
  # Hierarchical Clustering
  if ("hierarchical" %in% clustering_methods) {
    cat("   🌳 Hierarchical clustering...\n")
    similarity_results$clustering_results$hierarchical <- perform_hierarchical_clustering(
      distance_matrix = distance_matrix,
      metadata = metadata
    )
  }
  
  # K-means Clustering
  if ("kmeans" %in% clustering_methods) {
    cat("   🎯 K-means clustering...\n")
    similarity_results$clustering_results$kmeans <- perform_kmeans_clustering(
      dfm_tfidf = dfm_tfidf,
      metadata = metadata
    )
  }
  
  # DBSCAN Clustering
  if ("dbscan" %in% clustering_methods) {
    cat("   🔍 DBSCAN clustering...\n")
    similarity_results$clustering_results$dbscan <- perform_dbscan_clustering(
      distance_matrix = distance_matrix,
      metadata = metadata
    )
  }
  
  # Create document embeddings for visualization
  cat("📊 Creating document embeddings for visualization...\n")
  similarity_results$document_embeddings <- create_document_embeddings(
    dfm_tfidf = dfm_tfidf,
    similarity_matrix = primary_similarity
  )
  
  # Build similarity network
  cat("🕸️ Building document similarity network...\n")
  similarity_results$similarity_network <- build_similarity_network(
    similarity_matrix = primary_similarity,
    threshold = 0.3,
    metadata = metadata
  )
  
  # Generate interactive visualizations
  if (interactive) {
    cat("🎨 Generating interactive visualizations...\n")
    similarity_results$interactive_visualizations <- generate_similarity_visualizations(
      similarity_results = similarity_results,
      metadata = metadata
    )
  }
  
  # Processing metadata
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  similarity_results$processing_metadata <- list(
    documents_processed = length(texts),
    similarity_methods_used = similarity_methods,
    clustering_methods_used = clustering_methods,
    vocabulary_size = ncol(dfm_quanteda),
    processing_time_minutes = processing_time,
    analysis_timestamp = Sys.time()
  )
  
  cat("🎉 Comprehensive similarity analysis completed!\n")
  cat("⏱️ Processing time:", round(processing_time, 2), "minutes\n")
  
  return(similarity_results)
}

#' Advanced Keyword-in-Context (KWIC) Analysis
#' 
#' Comprehensive KWIC analysis with collocation detection, frequency analysis,
#' and contextual pattern identification for Portuguese legal texts
#' 
#' @param texts Vector of texts
#' @param keywords Vector of keywords to analyze
#' @param window_size Context window size
#' @param metadata Document metadata
#' @return KWIC analysis results with visualizations
advanced_kwic_analysis <- function(texts, 
                                  keywords = NULL,
                                  window_size = 10,
                                  metadata = NULL) {
  
  start_time <- Sys.time()
  cat("🔍 Advanced Keyword-in-Context (KWIC) Analysis\n")
  cat("📊 Processing", length(texts), "documents\n")
  
  # Initialize results
  kwic_results <- list(
    keyword_contexts = list(),
    collocation_analysis = list(),
    frequency_analysis = list(),
    contextual_patterns = list(),
    temporal_patterns = NULL,
    interactive_kwic = NULL,
    processing_metadata = list()
  )
  
  # Prepare corpus
  corpus_quanteda <- corpus(texts)
  tokens_quanteda <- tokens(corpus_quanteda, what = "word", remove_punct = TRUE)
  
  # Auto-detect important keywords if not provided
  if (is.null(keywords)) {
    cat("🎯 Auto-detecting important keywords...\n")
    keywords <- auto_detect_keywords(texts, n_keywords = 50)
  }
  
  cat("🔍 Analyzing", length(keywords), "keywords\n")
  
  # KWIC analysis for each keyword
  for (keyword in keywords) {
    cat("   📝 Analyzing keyword:", keyword, "\n")
    
    # Extract KWIC contexts
    kwic_contexts <- quanteda::kwic(
      tokens_quanteda, 
      pattern = keyword,
      window = window_size,
      case_insensitive = TRUE
    )
    
    if (nrow(kwic_contexts) > 0) {
      kwic_results$keyword_contexts[[keyword]] <- kwic_contexts %>%
        as_tibble() %>%
        mutate(
          full_context = paste(pre, keyword, post, sep = " "),
          keyword = keyword,
          context_length = nchar(full_context)
        )
      
      # Collocation analysis
      collocations <- textstat_collocations(
        tokens_quanteda,
        pattern = keyword,
        size = 2:3,
        min_count = 3
      )
      
      if (nrow(collocations) > 0) {
        kwic_results$collocation_analysis[[keyword]] <- collocations %>%
          as_tibble() %>%
          arrange(desc(z)) %>%
          head(20)
      }
    }
  }
  
  # Frequency analysis
  cat("📊 Computing frequency statistics...\n")
  kwic_results$frequency_analysis <- compute_keyword_frequencies(
    texts = texts,
    keywords = keywords,
    metadata = metadata
  )
  
  # Contextual pattern analysis
  cat("🔍 Identifying contextual patterns...\n")
  kwic_results$contextual_patterns <- identify_contextual_patterns(
    kwic_results$keyword_contexts
  )
  
  # Temporal analysis if metadata available
  if (!isTRUE(is.null(metadata)) && "ano" %in% names(metadata)) {
    cat("📈 Analyzing temporal keyword patterns...\n")
    kwic_results$temporal_patterns <- analyze_temporal_keyword_patterns(
      kwic_results = kwic_results,
      metadata = metadata
    )
  }
  
  # Generate interactive KWIC browser
  cat("🎨 Creating interactive KWIC browser...\n")
  kwic_results$interactive_kwic <- create_interactive_kwic_browser(
    kwic_results = kwic_results,
    metadata = metadata
  )
  
  # Processing metadata
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  kwic_results$processing_metadata <- list(
    documents_processed = length(texts),
    keywords_analyzed = length(keywords),
    total_kwic_instances = sum(sapply(kwic_results$keyword_contexts, nrow)),
    processing_time_minutes = processing_time,
    analysis_timestamp = Sys.time()
  )
  
  cat("🎉 Advanced KWIC analysis completed!\n")
  cat("📊 Total KWIC instances:", kwic_results$processing_metadata$total_kwic_instances, "\n")
  cat("⏱️ Processing time:", round(processing_time, 2), "minutes\n")
  
  return(kwic_results)
}

# Academic Research Features ==============================================

#' Generate Academic Research Report for Text Analytics
#' 
#' Creates comprehensive, publication-ready research reports with statistical
#' analyses, visualizations, and academic formatting standards
#' 
#' @param nlp_results Comprehensive NLP analysis results
#' @param metadata Document metadata
#' @param research_questions Vector of research questions to address
#' @param output_format Output format c("pdf", "html", "word", "all")
#' @param citation_style Citation style c("apa", "abnt", "chicago")
#' @return Generated research report paths and statistical summaries
generate_academic_research_report <- function(nlp_results,
                                             metadata = NULL,
                                             research_questions = NULL,
                                             output_format = "pdf",
                                             citation_style = "abnt") {
  
  start_time <- Sys.time()
  cat("📄 Generating Academic Research Report\n")
  cat("🎯 Output format:", output_format, "\n")
  cat("📚 Citation style:", citation_style, "\n")
  
  # Initialize report structure
  report_results <- list(
    statistical_analyses = list(),
    research_findings = list(),
    generated_reports = list(),
    bibliographic_data = list(),
    reproducibility_info = list()
  )
  
  # Statistical Analysis Section
  cat("📊 Conducting statistical analyses...\n")
  
  # Descriptive statistics
  report_results$statistical_analyses$descriptive <- compute_descriptive_statistics(
    nlp_results = nlp_results,
    metadata = metadata
  )
  
  # Inferential statistics  
  if (!is.null(metadata)) {
    report_results$statistical_analyses$inferential <- conduct_inferential_tests(
      nlp_results = nlp_results,
      metadata = metadata
    )
  }
  
  # Effect size calculations
  report_results$statistical_analyses$effect_sizes <- compute_effect_sizes(
    nlp_results = nlp_results,
    metadata = metadata
  )
  
  # Research findings synthesis
  cat("🔍 Synthesizing research findings...\n")
  report_results$research_findings <- synthesize_research_findings(
    statistical_analyses = report_results$statistical_analyses,
    research_questions = research_questions,
    nlp_results = nlp_results
  )
  
  # Generate academic visualizations
  cat("📊 Creating academic-quality visualizations...\n")
  academic_plots <- create_academic_visualizations(
    nlp_results = nlp_results,
    statistical_analyses = report_results$statistical_analyses,
    metadata = metadata
  )
  
  # Create bibliographic entries
  cat("📚 Preparing bibliographic data...\n")
  report_results$bibliographic_data <- create_bibliographic_entries(
    nlp_results = nlp_results,
    metadata = metadata,
    citation_style = citation_style
  )
  
  # Generate reproducibility information
  cat("🔁 Recording reproducibility information...\n")
  report_results$reproducibility_info <- generate_reproducibility_info()
  
  # Create R Markdown report
  cat("📝 Generating R Markdown report...\n")
  report_template <- create_academic_report_template(
    results = report_results,
    plots = academic_plots,
    metadata = metadata,
    citation_style = citation_style
  )
  
  # Render reports in specified formats
  cat("🖨️ Rendering reports...\n")
  report_results$generated_reports <- render_academic_reports(
    template = report_template,
    output_format = output_format
  )
  
  # Processing metadata
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  
  cat("🎉 Academic research report generated successfully!\n")
  cat("📄 Report files:", length(report_results$generated_reports), "\n")
  cat("⏱️ Processing time:", round(processing_time, 2), "minutes\n")
  
  return(report_results)
}

#' Statistical Hypothesis Testing for Text Analytics
#' 
#' Comprehensive statistical testing framework for text analysis results
#' with multiple comparison corrections and effect size reporting
#' 
#' @param nlp_results NLP analysis results
#' @param metadata Document metadata with grouping variables
#' @param hypotheses List of hypotheses to test
#' @param alpha Significance level
#' @return Statistical test results with corrections and interpretations
statistical_hypothesis_testing <- function(nlp_results,
                                          metadata,
                                          hypotheses = NULL,
                                          alpha = 0.05) {
  
  start_time <- Sys.time()
  cat("🧪 Statistical Hypothesis Testing for Text Analytics\n")
  cat("📊 Significance level: α =", alpha, "\n")
  
  # Initialize test results
  test_results <- list(
    hypothesis_tests = list(),
    multiple_comparisons = list(),
    effect_sizes = list(),
    power_analyses = list(),
    assumptions_checks = list(),
    interpretations = list()
  )
  
  # Prepare data for analysis
  analysis_data <- prepare_hypothesis_testing_data(nlp_results, metadata)
  
  # Default hypotheses if none provided
  if (is.null(hypotheses)) {
    hypotheses <- generate_default_hypotheses(analysis_data)
  }
  
  cat("🎯 Testing", length(hypotheses), "hypotheses\n")
  
  # Test each hypothesis
  for (i in seq_along(hypotheses)) {
    hypothesis <- hypotheses[[i]]
    cat("   📋 Testing:", hypothesis$description, "\n")
    
    # Select appropriate test
    test_result <- conduct_statistical_test(
      data = analysis_data,
      hypothesis = hypothesis,
      alpha = alpha
    )
    
    test_results$hypothesis_tests[[i]] <- test_result
    
    # Check assumptions
    test_results$assumptions_checks[[i]] <- check_test_assumptions(
      data = analysis_data,
      test_type = test_result$test_type
    )
    
    # Calculate effect sizes
    test_results$effect_sizes[[i]] <- calculate_effect_size(
      test_result = test_result,
      data = analysis_data
    )
    
    # Power analysis
    test_results$power_analyses[[i]] <- conduct_power_analysis(
      test_result = test_result,
      alpha = alpha
    )
  }
  
  # Multiple comparison corrections
  cat("🔧 Applying multiple comparison corrections...\n")
  test_results$multiple_comparisons <- apply_multiple_comparison_corrections(
    test_results$hypothesis_tests,
    methods = c("bonferroni", "holm", "fdr")
  )
  
  # Generate interpretations
  cat("📝 Generating statistical interpretations...\n")
  test_results$interpretations <- generate_statistical_interpretations(
    test_results = test_results,
    alpha = alpha
  )
  
  # Create summary table
  test_results$summary_table <- create_hypothesis_testing_summary_table(
    test_results = test_results
  )
  
  # Processing metadata
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  
  cat("🎉 Statistical hypothesis testing completed!\n")
  cat("📊 Significant results:", sum(sapply(test_results$hypothesis_tests, function(x) x$p_value < alpha)), "\n")
  cat("⏱️ Processing time:", round(processing_time, 2), "minutes\n")
  
  return(test_results)
}

# Helper Functions for Interactive Features ==============================

#' Auto-detect Important Keywords
auto_detect_keywords <- function(texts, n_keywords = 50) {
  # Create corpus and extract high-frequency, high-importance terms
  corpus_quanteda <- corpus(texts)
  tokens_quanteda <- tokens(corpus_quanteda, remove_punct = TRUE) %>%
    tokens_tolower() %>%
    tokens_remove(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_stopwords)
  
  dfm_quanteda <- dfm(tokens_quanteda) %>%
    dfm_trim(min_docfreq = 5)
  
  # Calculate TF-IDF and extract top terms
  dfm_tfidf <- dfm_weight(dfm_quanteda, scheme = "tfidf")
  
  keyword_scores <- textstat_frequency(dfm_tfidf) %>%
    arrange(desc(frequency)) %>%
    head(n_keywords) %>%
    pull(feature)
  
  return(keyword_scores)
}

#' Compute Cosine Similarity Matrix
compute_cosine_similarity_matrix <- function(dfm_tfidf) {
  # Convert to matrix and compute cosine similarity
  tfidf_matrix <- as.matrix(dfm_tfidf)
  
  # Normalize rows for cosine similarity
  row_norms <- sqrt(rowSums(tfidf_matrix^2))
  normalized_matrix <- tfidf_matrix / row_norms
  
  # Compute similarity matrix
  similarity_matrix <- normalized_matrix %*% t(normalized_matrix)
  
  return(similarity_matrix)
}

#' Create Document Embeddings
create_document_embeddings <- function(dfm_tfidf, similarity_matrix) {
  # Use multidimensional scaling to create 2D embeddings
  distance_matrix <- 1 - similarity_matrix
  
  # Classical MDS
  mds_result <- cmdscale(distance_matrix, k = 2, eig = TRUE)
  
  embeddings <- tibble(
    doc_id = 1:nrow(mds_result$points),
    x = mds_result$points[, 1],
    y = mds_result$points[, 2],
    eigenvalue_1 = mds_result$eig[1],
    eigenvalue_2 = mds_result$eig[2]
  )
  
  return(embeddings)
}

# Export message
cat("✅ Interactive Text Exploration and Academic Research Features loaded!\n")
cat("🔧 Available advanced functions:\n") 
cat("   - comprehensive_text_similarity_analysis(): Document similarity and clustering\n")
cat("   - advanced_kwic_analysis(): Keyword-in-context analysis\n")
cat("   - generate_academic_research_report(): Publication-ready research reports\n")
cat("   - statistical_hypothesis_testing(): Comprehensive statistical testing\n")
cat("📚 Ready for advanced academic research in Portuguese legal text analysis!\n")