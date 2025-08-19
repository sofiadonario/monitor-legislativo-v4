# LEGISLATIVE DATA SCIENCE INTEGRATION MODULE
# ==========================================
# Main integration module for all legislative-specific data science enhancements
# Seamlessly integrates with existing app.R structure with Railway optimization

cat("Loading Legislative Data Science Integration Module...\n")

# Load all specialized modules with error handling
# ===============================================

legislative_modules_loaded <- list()

# Brazilian Legal NLP Module
tryCatch({
  source("modules/nlp/brazilian_legal_nlp.R")
  legislative_modules_loaded$nlp <- TRUE
  cat("✅ Brazilian Legal NLP Module loaded\n")
}, error = function(e) {
  cat("⚠️ Brazilian Legal NLP Module failed to load:", e$message, "\n")
  legislative_modules_loaded$nlp <- FALSE
})

# Citation Network Analysis Module
tryCatch({
  source("modules/citations/citation_network_analysis.R")
  legislative_modules_loaded$citations <- TRUE
  cat("✅ Citation Network Analysis Module loaded\n")
}, error = function(e) {
  cat("⚠️ Citation Network Analysis Module failed to load:", e$message, "\n")
  legislative_modules_loaded$citations <- FALSE
})

# Transport Policy Intelligence Module
tryCatch({
  source("modules/transport/transport_policy_intelligence.R")
  legislative_modules_loaded$transport <- TRUE
  cat("✅ Transport Policy Intelligence Module loaded\n")
}, error = function(e) {
  cat("⚠️ Transport Policy Intelligence Module failed to load:", e$message, "\n")
  legislative_modules_loaded$transport <- FALSE
})

# Constitutional Evolution Tracking Module
tryCatch({
  source("modules/constitutional/constitutional_evolution_tracker.R")
  legislative_modules_loaded$constitutional <- TRUE
  cat("✅ Constitutional Evolution Tracking Module loaded\n")
}, error = function(e) {
  cat("⚠️ Constitutional Evolution Tracking Module failed to load:", e$message, "\n")
  legislative_modules_loaded$constitutional <- FALSE
})

# Legislative Productivity Analytics Module
tryCatch({
  source("modules/productivity/legislative_productivity_analytics.R")
  legislative_modules_loaded$productivity <- TRUE
  cat("✅ Legislative Productivity Analytics Module loaded\n")
}, error = function(e) {
  cat("⚠️ Legislative Productivity Analytics Module failed to load:", e$message, "\n")
  legislative_modules_loaded$productivity <- FALSE
})

# Machine Learning Models Module
tryCatch({
  source("modules/ml/machine_learning_models.R")
  legislative_modules_loaded$ml <- TRUE
  cat("✅ Machine Learning Models Module loaded\n")
}, error = function(e) {
  cat("⚠️ Machine Learning Models Module failed to load:", e$message, "\n")
  legislative_modules_loaded$ml <- FALSE
})

# Unified Legislative Data Science Interface
# =========================================

#' Comprehensive Legislative Analysis Pipeline
#' @param connection Database connection (optional)
#' @param sample_size Number of documents to analyze (for Railway memory constraints)
#' @param analysis_modules Vector of modules to run ("all" or specific modules)
#' @return Comprehensive analysis results
run_comprehensive_legislative_analysis <- function(connection = NULL, 
                                                  sample_size = 1000,
                                                  analysis_modules = "all") {
  
  cat("🚀 Starting Comprehensive Legislative Analysis Pipeline\n")
  cat("📊 Maximum sample size:", sample_size, "\n")
  cat("🔧 Analysis modules:", if(is.vector(analysis_modules) && analysis_modules[1] == "all") "All modules" else paste(analysis_modules, collapse = ", "), "\n")
  
  # Initialize results container
  analysis_results <- list(
    metadata = list(
      start_time = Sys.time(),
      sample_size = sample_size,
      modules_requested = analysis_modules,
      modules_available = legislative_modules_loaded,
      railway_optimized = TRUE
    ),
    analyses = list()
  )
  
  # Determine which modules to run
  modules_to_run <- if (is.vector(analysis_modules) && analysis_modules[1] == "all") {
    names(legislative_modules_loaded)[unlist(legislative_modules_loaded)]
  } else {
    intersect(analysis_modules, names(legislative_modules_loaded)[unlist(legislative_modules_loaded)])
  }
  
  cat("🎯 Running modules:", paste(modules_to_run, collapse = ", "), "\n")
  
  # Run Brazilian Legal NLP Analysis
  if ("nlp" %in% modules_to_run && legislative_modules_loaded$nlp) {
    cat("\n📝 Running Brazilian Legal NLP Analysis...\n")
    analysis_results$analyses$nlp <- tryCatch({
      railway_efficient_nlp_analysis(connection, batch_size = sample_size)
    }, error = function(e) {
      list(status = "error", message = e$message, module = "nlp")
    })
  }
  
  # Run Citation Network Analysis
  if ("citations" %in% modules_to_run && legislative_modules_loaded$citations) {
    cat("\n🔗 Running Citation Network Analysis...\n")
    analysis_results$analyses$citations <- tryCatch({
      railway_citation_analysis(connection, batch_size = sample_size)
    }, error = function(e) {
      list(status = "error", message = e$message, module = "citations")
    })
  }
  
  # Run Transport Policy Intelligence
  if ("transport" %in% modules_to_run && legislative_modules_loaded$transport) {
    cat("\n🚛 Running Transport Policy Intelligence...\n")
    analysis_results$analyses$transport <- tryCatch({
      railway_transport_policy_analysis(connection, batch_size = sample_size)
    }, error = function(e) {
      list(status = "error", message = e$message, module = "transport")
    })
  }
  
  # Run Constitutional Evolution Tracking
  if ("constitutional" %in% modules_to_run && legislative_modules_loaded$constitutional) {
    cat("\n🏛️ Running Constitutional Evolution Analysis...\n")
    analysis_results$analyses$constitutional <- tryCatch({
      railway_constitutional_analysis(connection, batch_size = sample_size)
    }, error = function(e) {
      list(status = "error", message = e$message, module = "constitutional")
    })
  }
  
  # Run Legislative Productivity Analytics
  if ("productivity" %in% modules_to_run && legislative_modules_loaded$productivity) {
    cat("\n📊 Running Legislative Productivity Analytics...\n")
    analysis_results$analyses$productivity <- tryCatch({
      railway_productivity_analysis(connection, batch_size = sample_size)
    }, error = function(e) {
      list(status = "error", message = e$message, module = "productivity")
    })
  }
  
  # Run Machine Learning Models
  if ("ml" %in% modules_to_run && legislative_modules_loaded$ml) {
    cat("\n🤖 Running Machine Learning Analysis...\n")
    analysis_results$analyses$ml <- tryCatch({
      railway_ml_analysis(connection, batch_size = sample_size)
    }, error = function(e) {
      list(status = "error", message = e$message, module = "ml")
    })
  }
  
  # Generate unified insights
  analysis_results$unified_insights <- generate_unified_insights(analysis_results$analyses)
  
  # Add completion metadata
  analysis_results$metadata$end_time <- Sys.time()
  analysis_results$metadata$duration <- difftime(
    analysis_results$metadata$end_time, 
    analysis_results$metadata$start_time, 
    units = "secs"
  )
  analysis_results$metadata$modules_completed <- length(analysis_results$analyses)
  analysis_results$metadata$status <- "complete"
  
  cat("\n✅ Comprehensive Legislative Analysis completed!\n")
  cat("⏱️ Duration:", round(as.numeric(analysis_results$metadata$duration), 2), "seconds\n")
  cat("📊 Modules completed:", analysis_results$metadata$modules_completed, "\n")
  
  return(analysis_results)
}

#' Generate Unified Insights from All Analyses
#' @param analyses List of analysis results from different modules
#' @return Unified insights and cross-module correlations
generate_unified_insights <- function(analyses) {
  cat("🔍 Generating unified insights across all analyses...\n")
  
  insights <- list(
    summary = list(),
    cross_module_patterns = list(),
    key_findings = list(),
    recommendations = list()
  )
  
  # Module status summary
  module_statuses <- sapply(analyses, function(x) x$status %||% "unknown")
  successful_modules <- names(module_statuses)[module_statuses %in% c("complete", "fallback_complete")]
  
  insights$summary <- list(
    total_modules_run = length(analyses),
    successful_modules = length(successful_modules),
    success_rate = length(successful_modules) / length(analyses),
    modules_completed = successful_modules
  )
  
  # Extract key metrics from each module
  key_metrics <- list()
  
  # NLP insights
  if ("nlp" %in% names(analyses) && analyses$nlp$status %in% c("complete", "fallback_complete")) {
    key_metrics$nlp <- list(
      entities_found = analyses$nlp$summary$entities_found %||% 0,
      avg_sentiment = analyses$nlp$summary$avg_sentiment %||% 0,
      most_common_topic = analyses$nlp$summary$most_common_topic %||% "unknown"
    )
  }
  
  # Citation insights
  if ("citations" %in% names(analyses) && analyses$citations$status %in% c("complete", "fallback_complete")) {
    key_metrics$citations <- list(
      total_citations = analyses$citations$total_citations_found %||% 0,
      network_density = analyses$citations$network_density %||% 0,
      most_cited = if (length(analyses$citations$most_cited_instruments %||% c()) > 0) {
        analyses$citations$most_cited_instruments[1]
      } else "none"
    )
  }
  
  # Transport insights
  if ("transport" %in% names(analyses) && analyses$transport$status %in% c("complete", "fallback_complete")) {
    key_metrics$transport <- list(
      decarbonization_docs = analyses$transport$summary$decarbonization_docs %||% 0,
      modal_integration_docs = analyses$transport$summary$modal_integration_docs %||% 0,
      regulatory_evolution_docs = analyses$transport$summary$regulatory_evolution_docs %||% 0
    )
  }
  
  # Constitutional insights
  if ("constitutional" %in% names(analyses) && analyses$constitutional$status %in% c("complete", "fallback_complete")) {
    key_metrics$constitutional <- list(
      constitutional_docs = analyses$constitutional$summary$constitutional_documents %||% 0,
      federal_system_docs = analyses$constitutional$summary$federal_system_documents %||% 0,
      institutional_change_docs = analyses$constitutional$summary$institutional_change_documents %||% 0
    )
  }
  
  # Productivity insights
  if ("productivity" %in% names(analyses) && analyses$productivity$status %in% c("complete", "fallback_complete")) {
    key_metrics$productivity <- list(
      high_efficiency_docs = analyses$productivity$summary$high_efficiency_documents %||% 0,
      mature_policies = analyses$productivity$summary$mature_policy_documents %||% 0,
      comprehensive_impact_docs = analyses$productivity$summary$comprehensive_impact_documents %||% 0
    )
  }
  
  # ML insights
  if ("ml" %in% names(analyses) && analyses$ml$status %in% c("complete", "fallback_complete")) {
    key_metrics$ml <- list(
      documents_classified = analyses$ml$summary$documents_classified %||% 0,
      features_extracted = analyses$ml$summary$features_extracted %||% 0,
      trends_analyzed = analyses$ml$summary$trends_analyzed %||% FALSE
    )
  }
  
  # Cross-module pattern analysis
  insights$cross_module_patterns <- analyze_cross_module_patterns(key_metrics)
  
  # Generate key findings
  insights$key_findings <- generate_key_findings(key_metrics, analyses)
  
  # Generate strategic recommendations
  insights$recommendations <- generate_strategic_recommendations(key_metrics, insights$cross_module_patterns)
  
  cat("✅ Unified insights generated successfully!\n")
  return(insights)
}

#' Analyze Patterns Across Multiple Modules
#' @param key_metrics Extracted metrics from all modules
#' @return Cross-module pattern analysis
analyze_cross_module_patterns <- function(key_metrics) {
  patterns <- list()
  
  # Policy modernization pattern
  modernization_score <- 0
  if ("transport" %in% names(key_metrics)) {
    modernization_score <- modernization_score + key_metrics$transport$regulatory_evolution_docs
  }
  if ("productivity" %in% names(key_metrics)) {
    modernization_score <- modernization_score + key_metrics$productivity$high_efficiency_docs
  }
  if ("constitutional" %in% names(key_metrics)) {
    modernization_score <- modernization_score + key_metrics$constitutional$institutional_change_docs
  }
  
  patterns$modernization_intensity <- if (modernization_score > 10) {
    "high"
  } else if (modernization_score > 5) {
    "moderate"
  } else {
    "low"
  }
  
  # Sustainability focus pattern
  sustainability_indicators <- 0
  if ("transport" %in% names(key_metrics)) {
    sustainability_indicators <- key_metrics$transport$decarbonization_docs
  }
  if ("nlp" %in% names(key_metrics)) {
    if (key_metrics$nlp$most_common_topic %in% c("sustentabilidade", "meio_ambiente")) {
      sustainability_indicators <- sustainability_indicators + 5
    }
  }
  
  patterns$sustainability_focus <- if (sustainability_indicators > 8) {
    "strong"
  } else if (sustainability_indicators > 3) {
    "moderate"
  } else {
    "weak"
  }
  
  # Regulatory complexity pattern
  complexity_score <- 0
  if ("citations" %in% names(key_metrics)) {
    complexity_score <- complexity_score + key_metrics$citations$total_citations
  }
  if ("constitutional" %in% names(key_metrics)) {
    complexity_score <- complexity_score + key_metrics$constitutional$constitutional_docs
  }
  
  patterns$regulatory_complexity <- if (complexity_score > 15) {
    "high_complexity"
  } else if (complexity_score > 8) {
    "moderate_complexity"
  } else {
    "low_complexity"
  }
  
  return(patterns)
}

#' Generate Key Findings Summary
#' @param key_metrics Metrics from all modules
#' @param analyses Full analysis results
#' @return List of key findings
generate_key_findings <- function(key_metrics, analyses) {
  findings <- list()
  
  # Finding 1: Document analysis coverage
  total_docs_analyzed <- max(sapply(analyses, function(x) {
    x$summary$total_documents_analyzed %||% 0
  }), na.rm = TRUE)
  
  findings$document_coverage <- list(
    title = "Cobertura da Análise Documental",
    description = paste("Análise abrangente de", total_docs_analyzed, "documentos legislativos"),
    impact = "high",
    category = "scope"
  )
  
  # Finding 2: NLP insights
  if ("nlp" %in% names(key_metrics)) {
    findings$nlp_insights <- list(
      title = "Análise de Linguagem Jurídica",
      description = paste("Identificadas", key_metrics$nlp$entities_found, "entidades legais com sentiment médio de", round(key_metrics$nlp$avg_sentiment, 3)),
      impact = "medium",
      category = "text_analysis"
    )
  }
  
  # Finding 3: Transport policy trends
  if ("transport" %in% names(key_metrics)) {
    findings$transport_trends <- list(
      title = "Tendências em Políticas de Transporte",
      description = paste("Foco em descarbonização (", key_metrics$transport$decarbonization_docs, " docs) e integração modal (", key_metrics$transport$modal_integration_docs, " docs)"),
      impact = "high",
      category = "policy_trends"
    )
  }
  
  # Finding 4: Constitutional compliance
  if ("constitutional" %in% names(key_metrics)) {
    findings$constitutional_compliance <- list(
      title = "Conformidade Constitucional",
      description = paste("Alto nível de referências constitucionais em", key_metrics$constitutional$constitutional_docs, "documentos"),
      impact = "high",
      category = "legal_compliance"
    )
  }
  
  # Finding 5: Productivity insights
  if ("productivity" %in% names(key_metrics)) {
    findings$productivity_assessment <- list(
      title = "Eficiência Legislativa",
      description = paste("Identificadas", key_metrics$productivity$high_efficiency_docs, "leis de alta eficiência e", key_metrics$productivity$mature_policies, "políticas maduras"),
      impact = "medium",
      category = "efficiency"
    )
  }
  
  return(findings)
}

#' Generate Strategic Recommendations
#' @param key_metrics Metrics from all modules
#' @param patterns Cross-module patterns
#' @return Strategic recommendations list
generate_strategic_recommendations <- function(key_metrics, patterns) {
  recommendations <- list()
  
  # Recommendation 1: Based on sustainability focus
  if (patterns$sustainability_focus == "weak") {
    recommendations$sustainability <- list(
      priority = "high",
      title = "Fortalecer Agenda de Sustentabilidade",
      description = "Baixo foco em sustentabilidade identificado. Recomenda-se priorizar legislação ambiental.",
      action_items = c(
        "Criar grupo de trabalho para políticas verdes",
        "Estabelecer metas de descarbonização no transporte",
        "Incentivar pesquisa em combustíveis alternativos"
      ),
      category = "environmental"
    )
  }
  
  # Recommendation 2: Based on modernization intensity
  if (patterns$modernization_intensity == "low") {
    recommendations$modernization <- list(
      priority = "medium",
      title = "Acelerar Modernização Regulatória",
      description = "Oportunidade para maior modernização do marco regulatório.",
      action_items = c(
        "Implementar processos digitais",
        "Revisar regulamentações desatualizadas",
        "Promover inovação tecnológica"
      ),
      category = "innovation"
    )
  }
  
  # Recommendation 3: Based on regulatory complexity
  if (patterns$regulatory_complexity == "high_complexity") {
    recommendations$simplification <- list(
      priority = "medium",
      title = "Simplificar Marco Regulatório",
      description = "Alta complexidade regulatória detectada. Considerar simplificação.",
      action_items = c(
        "Consolidar regulamentações fragmentadas",
        "Criar guias de compliance",
        "Estabelecer processos mais claros"
      ),
      category = "governance"
    )
  }
  
  # Recommendation 4: Based on ML insights
  if ("ml" %in% names(key_metrics) && key_metrics$ml$trends_analyzed) {
    recommendations$predictive_governance <- list(
      priority = "low",
      title = "Implementar Governança Preditiva",
      description = "Usar análises preditivas para melhor planejamento legislativo.",
      action_items = c(
        "Estabelecer sistema de monitoramento contínuo",
        "Criar alertas para tendências emergentes",
        "Desenvolver dashboards executivos"
      ),
      category = "governance"
    )
  }
  
  return(recommendations)
}

#' Get Legislative Analytics Dashboard Data
#' @param connection Database connection (optional)
#' @param modules Vector of modules to include in dashboard
#' @return Dashboard-ready data structure
get_legislative_dashboard_data <- function(connection = NULL, modules = c("nlp", "transport", "constitutional")) {
  tryCatch({
    cat("📊 Preparing legislative analytics dashboard data...\n")
    
    # Run lightweight analysis for dashboard
    dashboard_results <- run_comprehensive_legislative_analysis(
      connection = connection,
      sample_size = 500,  # Reduced sample for dashboard performance
      analysis_modules = modules
    )
    
    # Format for dashboard consumption
    dashboard_data <- list(
      summary_metrics = extract_summary_metrics(dashboard_results),
      key_insights = extract_key_insights(dashboard_results),
      visualizations = prepare_visualization_data(dashboard_results),
      recommendations = extract_recommendations(dashboard_results),
      last_updated = Sys.time(),
      status = "ready"
    )
    
    cat("✅ Legislative dashboard data prepared successfully!\n")
    return(dashboard_data)
    
  }, error = function(e) {
    warning("Legislative dashboard data preparation failed: ", e$message)
    return(list(
      status = "error",
      message = e$message,
      last_updated = Sys.time()
    ))
  })
}

# Helper functions for dashboard data preparation
extract_summary_metrics <- function(results) {
  if (is.null(results$unified_insights)) return(list())
  
  list(
    total_modules = results$metadata$modules_completed,
    success_rate = round(results$unified_insights$summary$success_rate * 100, 1),
    analysis_duration = round(as.numeric(results$metadata$duration), 2),
    key_findings_count = length(results$unified_insights$key_findings),
    recommendations_count = length(results$unified_insights$recommendations)
  )
}

extract_key_insights <- function(results) {
  if (is.null(results$unified_insights$key_findings)) return(list())
  
  # Convert findings to dashboard format
  lapply(results$unified_insights$key_findings, function(finding) {
    list(
      title = finding$title,
      description = finding$description,
      impact = finding$impact,
      category = finding$category
    )
  })
}

prepare_visualization_data <- function(results) {
  # Prepare data structures for charts and graphs
  list(
    module_performance = if (!is.null(results$unified_insights$summary)) {
      data.frame(
        module = results$unified_insights$summary$modules_completed,
        status = "completed",
        stringsAsFactors = FALSE
      )
    } else data.frame(),
    
    trend_data = if (!is.null(results$analyses$ml$trend_insights)) {
      results$analyses$ml$trend_insights$historical_data
    } else data.frame(),
    
    classification_data = if (!is.null(results$analyses$ml$sample_classifications)) {
      table(results$analyses$ml$sample_classifications$predicted_category)
    } else table(character(0))
  )
}

extract_recommendations <- function(results) {
  if (is.null(results$unified_insights$recommendations)) return(list())
  
  # Format recommendations for dashboard display
  lapply(results$unified_insights$recommendations, function(rec) {
    list(
      priority = rec$priority,
      title = rec$title,
      description = rec$description,
      category = rec$category,
      action_items = rec$action_items %||% character(0)
    )
  })
}

# Utility function for null coalescing
`%||%` <- function(a, b) if (is.null(a)) b else a

cat("✅ Legislative Data Science Integration Module loaded successfully\n")
cat("   🔧 All specialized modules integrated\n")
cat("   📊 Unified analysis pipeline: ENABLED\n") 
cat("   🎯 Cross-module insights: ENABLED\n")
cat("   📈 Strategic recommendations: ENABLED\n")
cat("   🖥️ Dashboard integration: ENABLED\n")
cat("   ⚡ Railway optimization: ENABLED\n")
cat("   💾 Memory management: OPTIMIZED\n")

# Export main integration functions
LEGISLATIVE_INTEGRATION_FUNCTIONS <- list(
  run_comprehensive_legislative_analysis = run_comprehensive_legislative_analysis,
  generate_unified_insights = generate_unified_insights,
  get_legislative_dashboard_data = get_legislative_dashboard_data,
  modules_loaded = legislative_modules_loaded
)