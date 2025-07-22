# ====================================================================
# LexML Advanced Statistical Analysis Module
# Integrates statistical methods from R analysis folder for legislative data
# ====================================================================

# Load required packages with intelligent package management
if (!require("pacman")) install.packages("pacman")

pacman::p_load(
  # Statistical Testing
  automatedtests,      # Automated statistical test selection
  
  # Cluster Analysis  
  tidyclust,          # Clustering with tidy syntax
  NbClust,            # Optimal number of clusters
  clusterWebApp,      # Interactive clustering interface
  cluster,            # Classic clustering methods
  factoextra,         # Clustering visualization
  
  # Text Analysis & N-grams
  ngramr,             # Google Books N-gram analysis
  tm,                 # Text mining
  wordcloud2,         # Interactive word clouds
  
  # Count Data Analysis
  countfitteR,        # Distribution fitting for count data
  
  # Visualization & Graphics
  ggplot2,            # Professional graphics
  ggstatsplot,        # Statistical plots
  ggpubr,             # Publication-ready plots
  ggtext,             # Rich text in plots
  plotly,             # Interactive plots
  
  # Data Processing
  tidyverse,          # Data manipulation
  dplyr,              # Data wrangling
  janitor,            # Data cleaning
  
  # Database & Connection
  pool,               # Database connection pooling
  RPostgres,          # PostgreSQL interface
  
  # Additional utilities
  scales,             # Scale functions for ggplot2
  gt                  # Publication-quality tables
)

# ====================================================================
# 1. AUTOMATED STATISTICAL TESTING FOR LEGISLATIVE DATA
# ====================================================================

#' Perform automated statistical analysis on LexML data
#' @param db_pool Database connection pool
#' @param analysis_type Type of analysis to perform
#' @return List with test results and interpretations
perform_lexml_statistical_tests <- function(db_pool = NULL, analysis_type = "comprehensive") {
  
  if (is.null(db_pool)) {
    cat("⚠️ No database connection available\n")
    return(NULL)
  }
  
  tryCatch({
    # Get LexML data for analysis
    lexml_data <- get_lexml_statistical_data(db_pool)
    
    if (nrow(lexml_data) == 0) {
      cat("⚠️ No data available for statistical analysis\n")
      return(NULL)
    }
    
    results <- list()
    
    # 1. Document frequency by category
    if (analysis_type %in% c("comprehensive", "category")) {
      cat("📊 Testing document distribution by category...\n")
      
      category_counts <- table(lexml_data$categoria)
      category_test <- automatical_test(
        names(category_counts), 
        as.numeric(category_counts)
      )
      
      results$category_analysis <- list(
        test = category_test$get_test(),
        result = category_test$get_result(),
        significant = category_test$is_significant(),
        interpretation = ifelse(
          category_test$is_significant(),
          "Significant differences in document distribution across categories",
          "No significant differences in document distribution across categories"
        )
      )
    }
    
    # 2. Temporal patterns analysis
    if (analysis_type %in% c("comprehensive", "temporal")) {
      cat("📊 Testing temporal patterns in legislation...\n")
      
      # Extract year from date and count documents per year
      lexml_data$year <- as.numeric(format(as.Date(lexml_data$data), "%Y"))
      yearly_counts <- lexml_data %>%
        filter(!is.na(year) & year >= 1990 & year <= 2025) %>%
        count(year) %>%
        arrange(year)
      
      if (nrow(yearly_counts) > 5) {
        temporal_test <- automatical_test(yearly_counts$year, yearly_counts$n)
        
        results$temporal_analysis <- list(
          test = temporal_test$get_test(),
          result = temporal_test$get_result(),
          significant = temporal_test$is_significant(),
          trend_direction = ifelse(
            cor(yearly_counts$year, yearly_counts$n) > 0,
            "Increasing trend over time",
            "Decreasing trend over time"
          ),
          interpretation = paste(
            "Legislative activity shows",
            ifelse(temporal_test$is_significant(), "significant", "no significant"),
            "temporal variation"
          )
        )
      }
    }
    
    # 3. Jurisdictional differences
    if (analysis_type %in% c("comprehensive", "jurisdiction")) {
      cat("📊 Testing jurisdictional differences...\n")
      
      jurisdiction_data <- lexml_data %>%
        filter(!is.na(jurisdicao) & jurisdicao != "") %>%
        count(jurisdicao) %>%
        filter(n >= 5)  # Only include jurisdictions with sufficient data
      
      if (nrow(jurisdiction_data) > 2) {
        jurisdiction_test <- automatical_test(
          jurisdiction_data$jurisdicao,
          jurisdiction_data$n
        )
        
        results$jurisdiction_analysis <- list(
          test = jurisdiction_test$get_test(),
          result = jurisdiction_test$get_result(),
          significant = jurisdiction_test$is_significant(),
          interpretation = paste(
            ifelse(jurisdiction_test$is_significant(), "Significant", "No significant"),
            "differences in legislative activity across jurisdictions"
          )
        )
      }
    }
    
    # 4. State-level analysis
    if (analysis_type %in% c("comprehensive", "geographic")) {
      cat("📊 Testing geographic distribution patterns...\n")
      
      state_data <- lexml_data %>%
        filter(!is.na(estado) & estado != "") %>%
        count(estado) %>%
        arrange(desc(n)) %>%
        slice_head(n = 10)  # Top 10 states
      
      if (nrow(state_data) > 2) {
        geographic_test <- automatical_test(
          state_data$estado,
          state_data$n
        )
        
        results$geographic_analysis <- list(
          test = geographic_test$get_test(),
          result = geographic_test$get_result(),
          significant = geographic_test$is_significant(),
          top_states = paste(head(state_data$estado, 3), collapse = ", "),
          interpretation = paste(
            "Geographic distribution shows",
            ifelse(geographic_test$is_significant(), "significant", "balanced"),
            "concentration patterns"
          )
        )
      }
    }
    
    cat("✅ Statistical analysis completed\n")
    return(results)
    
  }, error = function(e) {
    cat("❌ Error in statistical analysis:", e$message, "\n")
    return(NULL)
  })
}

# ====================================================================
# 2. CLUSTER ANALYSIS FOR LEGISLATIVE DOCUMENTS  
# ====================================================================

#' Perform cluster analysis on LexML documents
#' @param db_pool Database connection pool
#' @param method Clustering method ("kmeans", "hierarchical", "auto")
#' @param max_clusters Maximum number of clusters to test
#' @return List with clustering results and visualizations
perform_lexml_cluster_analysis <- function(db_pool = NULL, method = "auto", max_clusters = 8) {
  
  if (is.null(db_pool)) {
    cat("⚠️ No database connection available\n")
    return(NULL)
  }
  
  tryCatch({
    # Get data for clustering
    cluster_data <- get_lexml_cluster_data(db_pool)
    
    if (nrow(cluster_data) < 10) {
      cat("⚠️ Insufficient data for cluster analysis\n")
      return(NULL)
    }
    
    # Prepare numeric data for clustering
    numeric_data <- cluster_data %>%
      select(where(is.numeric)) %>%
      na.omit() %>%
      scale()  # Standardize variables
    
    if (ncol(numeric_data) < 2) {
      cat("⚠️ Insufficient numeric variables for clustering\n")
      return(NULL)
    }
    
    results <- list()
    
    # Determine optimal number of clusters
    cat("🔄 Determining optimal number of clusters...\n")
    
    if (method == "auto" && nrow(numeric_data) > 30) {
      # Use NbClust for automatic selection
      nb_result <- NbClust(
        data = numeric_data,
        distance = "euclidean",
        min.nc = 2,
        max.nc = min(max_clusters, floor(nrow(numeric_data)/5)),
        method = "kmeans",
        index = "all"
      )
      
      optimal_k <- as.numeric(names(sort(table(nb_result$Best.nc[1, ]), decreasing = TRUE))[1])
      results$optimal_clusters <- optimal_k
      results$cluster_votes <- table(nb_result$Best.nc[1, ])
      
    } else {
      optimal_k <- 3  # Default fallback
      results$optimal_clusters <- optimal_k
    }
    
    # Perform K-means clustering using tidyclust
    cat("🔄 Performing cluster analysis...\n")
    
    mod_kmeans <- k_means(num_clusters = optimal_k) %>%
      set_engine("stats")
    
    fit_kmeans <- fit(mod_kmeans, ~., data = as.data.frame(numeric_data))
    
    # Get cluster predictions
    cluster_predictions <- augment(fit_kmeans, new_data = as.data.frame(numeric_data))
    
    # Extract centroids
    centroids <- extract_centroids(fit_kmeans)
    
    # Calculate quality metrics
    dists <- dist(numeric_data)
    
    results$model <- fit_kmeans
    results$predictions <- cluster_predictions
    results$centroids <- centroids
    results$silhouette_score <- silhouette_avg(fit_kmeans, dists = dists)
    results$sse_ratio <- sse_ratio(fit_kmeans)
    
    # Create cluster summary
    cluster_summary <- cluster_predictions %>%
      group_by(.pred_cluster) %>%
      summarise(
        n_documents = n(),
        avg_score = mean(rowMeans(select(., where(is.numeric))), na.rm = TRUE)
      )
    
    results$cluster_summary <- cluster_summary
    
    # Interpretation
    results$interpretation <- list(
      quality = ifelse(results$silhouette_score > 0.5, "Good", "Moderate"),
      clusters_found = optimal_k,
      largest_cluster = cluster_summary$n_documents[which.max(cluster_summary$n_documents)],
      recommendation = ifelse(
        results$silhouette_score > 0.5,
        "Clusters show good separation and can be used for document categorization",
        "Clusters show moderate separation - consider alternative grouping strategies"
      )
    )
    
    cat("✅ Cluster analysis completed\n")
    return(results)
    
  }, error = function(e) {
    cat("❌ Error in cluster analysis:", e$message, "\n")
    return(NULL)
  })
}

# ====================================================================
# 3. N-GRAM AND TEXT ANALYSIS FOR LEGISLATIVE DOCUMENTS
# ====================================================================

#' Perform N-gram analysis on legislative document titles
#' @param db_pool Database connection pool  
#' @param n_size Size of n-grams (1 = unigrams, 2 = bigrams, etc.)
#' @param min_freq Minimum frequency for inclusion
#' @return List with n-gram results and word clouds
perform_lexml_ngram_analysis <- function(db_pool = NULL, n_size = 2, min_freq = 3) {
  
  if (is.null(db_pool)) {
    cat("⚠️ No database connection available\n")
    return(NULL)
  }
  
  tryCatch({
    # Get text data
    text_data <- get_lexml_text_data(db_pool)
    
    if (nrow(text_data) == 0) {
      cat("⚠️ No text data available for analysis\n")
      return(NULL)
    }
    
    cat("🔄 Processing text data for N-gram analysis...\n")
    
    # Create text corpus
    corpus <- VCorpus(VectorSource(text_data$titulo))
    
    # Clean the corpus
    corpus_clean <- corpus %>%
      tm_map(removeNumbers) %>%
      tm_map(removePunctuation) %>%
      tm_map(content_transformer(tolower)) %>%
      tm_map(removeWords, stopwords("pt")) %>%  # Portuguese stopwords
      tm_map(removeWords, c("lei", "decreto", "portaria", "resolução", "instrução", "normativa")) %>%
      tm_map(stripWhitespace)
    
    # Create term document matrix
    if (n_size == 1) {
      tdm <- TermDocumentMatrix(corpus_clean)
    } else {
      # For n-grams > 1, use different tokenizer
      BigramTokenizer <- function(x) {
        unlist(lapply(ngrams(words(x), n_size), paste, collapse = " "), use.names = FALSE)
      }
      
      tdm <- TermDocumentMatrix(corpus_clean, control = list(tokenize = BigramTokenizer))
    }
    
    # Convert to matrix and get frequencies
    m <- as.matrix(tdm)
    word_freqs <- sort(rowSums(m), decreasing = TRUE)
    
    # Filter by minimum frequency
    word_freqs <- word_freqs[word_freqs >= min_freq]
    
    if (length(word_freqs) == 0) {
      cat("⚠️ No terms meet minimum frequency threshold\n")
      return(NULL)
    }
    
    # Create data frame for analysis
    df <- data.frame(
      term = names(word_freqs),
      freq = word_freqs,
      weight = word_freqs / sum(word_freqs) * 100
    )
    
    row.names(df) <- NULL
    df$weight <- round(df$weight, 2)
    
    results <- list()
    results$ngram_size <- n_size
    results$total_terms <- length(word_freqs)
    results$term_frequencies <- df
    results$top_terms <- head(df, 20)
    
    # Category-specific analysis if possible
    if ("categoria" %in% colnames(text_data)) {
      cat("🔄 Analyzing terms by category...\n")
      
      category_terms <- list()
      for (cat in unique(text_data$categoria)) {
        if (!is.na(cat) && cat != "") {
          cat_texts <- text_data[text_data$categoria == cat, "titulo"]
          if (length(cat_texts) > 5) {
            cat_corpus <- VCorpus(VectorSource(cat_texts)) %>%
              tm_map(removeNumbers) %>%
              tm_map(removePunctuation) %>%
              tm_map(content_transformer(tolower)) %>%
              tm_map(removeWords, stopwords("pt")) %>%
              tm_map(stripWhitespace)
            
            cat_tdm <- TermDocumentMatrix(cat_corpus)
            cat_m <- as.matrix(cat_tdm)
            cat_freqs <- sort(rowSums(cat_m), decreasing = TRUE)
            
            category_terms[[cat]] <- head(names(cat_freqs), 10)
          }
        }
      }
      results$category_terms <- category_terms
    }
    
    # Temporal trends if dates available
    if ("data" %in% colnames(text_data)) {
      cat("🔄 Analyzing temporal trends in terminology...\n")
      
      text_data$year <- format(as.Date(text_data$data), "%Y")
      yearly_terms <- text_data %>%
        filter(!is.na(year) & year >= "2000") %>%
        group_by(year) %>%
        summarise(
          total_docs = n(),
          avg_title_length = mean(nchar(titulo), na.rm = TRUE)
        )
      
      results$temporal_trends <- yearly_terms
    }
    
    results$interpretation <- list(
      most_common_term = df$term[1],
      term_diversity = paste("Found", nrow(df), "unique terms above frequency threshold"),
      coverage = paste(round(sum(head(df$freq, 10)) / sum(df$freq) * 100, 1), 
                      "% of terms covered by top 10 most frequent"),
      recommendation = ifelse(
        nrow(df) > 100,
        "High term diversity suggests rich vocabulary in legislative documents",
        "Moderate term diversity - consider expanding corpus or lowering frequency threshold"
      )
    )
    
    cat("✅ N-gram analysis completed\n")
    return(results)
    
  }, error = function(e) {
    cat("❌ Error in N-gram analysis:", e$message, "\n")
    return(NULL)
  })
}

# ====================================================================
# 4. COUNT DATA DISTRIBUTION ANALYSIS  
# ====================================================================

#' Analyze count data distributions in LexML dataset
#' @param db_pool Database connection pool
#' @param count_variables Vector of count variables to analyze
#' @return List with distribution analysis results
perform_lexml_count_analysis <- function(db_pool = NULL, count_variables = c("docs_per_state", "docs_per_year")) {
  
  if (is.null(db_pool)) {
    cat("⚠️ No database connection available\n")
    return(NULL)
  }
  
  tryCatch({
    # Get count data
    count_data <- get_lexml_count_data(db_pool)
    
    if (nrow(count_data) == 0) {
      cat("⚠️ No count data available for analysis\n")
      return(NULL)
    }
    
    cat("🔄 Analyzing count data distributions...\n")
    
    results <- list()
    
    # Process each count variable
    for (var in count_variables) {
      if (var %in% colnames(count_data)) {
        
        cat(paste("🔄 Analyzing distribution of", var, "...\n"))
        
        # Prepare data
        count_values <- count_data[[var]]
        count_values <- count_values[!is.na(count_values) & count_values >= 0]
        
        if (length(count_values) < 10) {
          next
        }
        
        # Create data frame for countfitteR
        var_df <- data.frame(counts = count_values)
        
        # Validate and process counts
        if (validate_counts(var_df)) {
          
          processed_counts <- process_counts(var_df)
          
          # Fit distribution models
          fitted_models <- fit_counts(processed_counts, model = "all")
          
          # Compare fits
          fit_comparison <- compare_fit(processed_counts, fitted_models)
          
          # Get summary and select best model
          model_summary <- summary_fitlist(fitted_models)
          best_model <- select_model(fitted_models)
          
          results[[var]] <- list(
            variable = var,
            n_observations = length(count_values),
            mean = mean(count_values),
            variance = var(count_values),
            zero_proportion = sum(count_values == 0) / length(count_values),
            fitted_models = fitted_models,
            fit_comparison = fit_comparison,
            model_summary = model_summary,
            best_model = best_model,
            interpretation = interpret_count_distribution(count_values, best_model)
          )
        }
      }
    }
    
    # Overall interpretation
    results$overall_interpretation <- list(
      variables_analyzed = length(results),
      common_patterns = identify_common_patterns(results),
      recommendations = generate_count_recommendations(results)
    )
    
    cat("✅ Count distribution analysis completed\n")
    return(results)
    
  }, error = function(e) {
    cat("❌ Error in count analysis:", e$message, "\n")
    return(NULL)
  })
}

# ====================================================================
# 5. HELPER FUNCTIONS FOR DATA RETRIEVAL
# ====================================================================

#' Get LexML data formatted for statistical analysis
get_lexml_statistical_data <- function(db_pool) {
  conn <- poolCheckout(db_pool)
  on.exit(poolReturn(conn))
  
  query <- "
    SELECT 
      categoria,
      jurisdicao,
      estado,
      municipio,
      data,
      tipo,
      titulo
    FROM lexml_documents 
    WHERE categoria IS NOT NULL 
    ORDER BY data DESC
    LIMIT 10000
  "
  
  dbGetQuery(conn, query)
}

#' Get data formatted for cluster analysis
get_lexml_cluster_data <- function(db_pool) {
  conn <- poolCheckout(db_pool)
  on.exit(poolReturn(conn))
  
  query <- "
    SELECT 
      LENGTH(titulo) as title_length,
      EXTRACT(YEAR FROM data) as year,
      CASE WHEN municipio IS NOT NULL THEN 1 ELSE 0 END as has_municipality,
      CASE 
        WHEN categoria = 'Legislação' THEN 1
        WHEN categoria = 'Jurisprudência' THEN 2  
        WHEN categoria = 'Doutrina' THEN 3
        ELSE 0 
      END as category_code,
      CASE
        WHEN jurisdicao = 'Federal' THEN 3
        WHEN jurisdicao = 'Estadual' THEN 2
        WHEN jurisdicao = 'Municipal' THEN 1
        ELSE 0
      END as jurisdiction_level
    FROM lexml_documents 
    WHERE data IS NOT NULL 
    AND categoria IS NOT NULL
    LIMIT 5000
  "
  
  dbGetQuery(conn, query)
}

#' Get text data for N-gram analysis
get_lexml_text_data <- function(db_pool) {
  conn <- poolCheckout(db_pool)
  on.exit(poolReturn(conn))
  
  query <- "
    SELECT 
      titulo,
      categoria,
      data,
      jurisdicao
    FROM lexml_documents 
    WHERE titulo IS NOT NULL 
    AND LENGTH(titulo) > 10
    ORDER BY data DESC
    LIMIT 5000
  "
  
  dbGetQuery(conn, query)
}

#' Get count data for distribution analysis
get_lexml_count_data <- function(db_pool) {
  conn <- poolCheckout(db_pool)
  on.exit(poolReturn(conn))
  
  # Get document counts by state and year
  query <- "
    WITH state_counts AS (
      SELECT estado, COUNT(*) as docs_per_state
      FROM lexml_documents 
      WHERE estado IS NOT NULL
      GROUP BY estado
    ),
    year_counts AS (
      SELECT EXTRACT(YEAR FROM data) as year, COUNT(*) as docs_per_year
      FROM lexml_documents 
      WHERE data IS NOT NULL
      GROUP BY EXTRACT(YEAR FROM data)
    )
    SELECT 
      s.docs_per_state,
      y.docs_per_year
    FROM state_counts s
    FULL OUTER JOIN year_counts y ON TRUE
    WHERE s.docs_per_state IS NOT NULL 
    OR y.docs_per_year IS NOT NULL
  "
  
  result <- dbGetQuery(poolCheckout(db_pool), query)
  poolReturn(poolCheckout(db_pool))
  
  return(result)
}

# ====================================================================
# 6. INTERPRETATION HELPER FUNCTIONS
# ====================================================================

interpret_count_distribution <- function(values, best_model) {
  mean_val <- mean(values)
  var_val <- var(values)
  zero_prop <- sum(values == 0) / length(values)
  
  if (zero_prop > 0.3) {
    return("High proportion of zeros - zero-inflated model likely appropriate")
  } else if (var_val > mean_val * 1.5) {
    return("Overdispersed data - negative binomial distribution likely appropriate")
  } else {
    return("Data shows Poisson-like characteristics")
  }
}

identify_common_patterns <- function(results) {
  if (length(results) == 0) return("No patterns identified")
  
  patterns <- c()
  
  # Check for zero inflation across variables
  zero_props <- sapply(results, function(x) {
    if ("zero_proportion" %in% names(x)) x$zero_proportion else NA
  })
  
  if (mean(zero_props, na.rm = TRUE) > 0.2) {
    patterns <- c(patterns, "High zero inflation across variables")
  }
  
  if (length(patterns) == 0) {
    patterns <- "Standard count distributions observed"
  }
  
  return(patterns)
}

generate_count_recommendations <- function(results) {
  if (length(results) == 0) return("No recommendations available")
  
  recommendations <- c(
    "Consider zero-inflated models for variables with high zero counts",
    "Use negative binomial models for overdispersed count data",
    "Regular monitoring of count distributions for anomaly detection"
  )
  
  return(recommendations)
}

# ====================================================================
# 7. MAIN ANALYSIS ORCHESTRATOR FUNCTION
# ====================================================================

#' Run comprehensive statistical analysis on LexML dataset
#' @param db_pool Database connection pool
#' @param analyses Vector of analyses to perform
#' @return Comprehensive analysis results
run_comprehensive_lexml_analysis <- function(db_pool = NULL, 
                                           analyses = c("statistical", "cluster", "ngram", "count")) {
  
  if (is.null(db_pool)) {
    cat("⚠️ No database connection available for analysis\n")
    return(NULL)
  }
  
  cat("🚀 Starting comprehensive LexML statistical analysis...\n")
  
  results <- list(
    timestamp = Sys.time(),
    analyses_performed = analyses
  )
  
  # Statistical testing
  if ("statistical" %in% analyses) {
    cat("\n=== AUTOMATED STATISTICAL TESTING ===\n")
    results$statistical_tests <- perform_lexml_statistical_tests(db_pool, "comprehensive")
  }
  
  # Cluster analysis
  if ("cluster" %in% analyses) {
    cat("\n=== CLUSTER ANALYSIS ===\n")
    results$cluster_analysis <- perform_lexml_cluster_analysis(db_pool, "auto", 8)
  }
  
  # N-gram analysis
  if ("ngram" %in% analyses) {
    cat("\n=== N-GRAM TEXT ANALYSIS ===\n")
    results$ngram_analysis <- perform_lexml_ngram_analysis(db_pool, 2, 3)
  }
  
  # Count distribution analysis
  if ("count" %in% analyses) {
    cat("\n=== COUNT DISTRIBUTION ANALYSIS ===\n")
    results$count_analysis <- perform_lexml_count_analysis(db_pool)
  }
  
  # Generate executive summary
  results$executive_summary <- generate_executive_summary(results)
  
  cat("\n✅ Comprehensive analysis completed!\n")
  cat("📊 Analysis summary available in results$executive_summary\n")
  
  return(results)
}

#' Generate executive summary of all analyses
generate_executive_summary <- function(results) {
  summary <- list(
    total_analyses = length(results$analyses_performed),
    key_findings = c(),
    recommendations = c(),
    data_quality = "Good"
  )
  
  # Extract key findings from each analysis
  if (!is.null(results$statistical_tests)) {
    summary$key_findings <- c(summary$key_findings, "Statistical patterns identified in legislative data")
  }
  
  if (!is.null(results$cluster_analysis)) {
    if (results$cluster_analysis$silhouette_score > 0.5) {
      summary$key_findings <- c(summary$key_findings, "Clear document clusters identified")
    }
  }
  
  if (!is.null(results$ngram_analysis)) {
    summary$key_findings <- c(summary$key_findings, 
                             paste("Rich terminology identified with", 
                                   results$ngram_analysis$total_terms, "unique terms"))
  }
  
  # Generate recommendations
  summary$recommendations <- c(
    "Continue monitoring statistical patterns for trend detection",
    "Use cluster analysis for automated document categorization", 
    "Leverage N-gram analysis for search term optimization",
    "Apply count models for predictive analytics"
  )
  
  return(summary)
}

cat("✅ LexML Advanced Statistical Analysis Module loaded successfully!\n")
cat("🎯 Main function: run_comprehensive_lexml_analysis(db_pool)\n")
cat("📊 Individual functions available for specific analyses\n")