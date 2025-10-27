# ============================================================================
# RECOMMENDATION ENGINE WITH COLLABORATIVE FILTERING - WEEK 10 PHASE 3
# ============================================================================
# 
# Intelligent recommendation system for Brazilian legislative research
# Monitor Legislativo v4 - Academic-focused personalized recommendations
# 
# Features:
# - Collaborative filtering for user-based recommendations
# - Content-based filtering using document similarity
# - Hybrid recommendation combining multiple approaches
# - Academic research workflow integration
# - Citation and reference recommendations
# - Topic-based discovery suggestions
# - Real-time recommendation updates
# - Performance optimization for large datasets
# ============================================================================

cat("🎯 Initializing Recommendation Engine - Week 10 Phase 3\n")
cat("🤝 Collaborative Filtering • Content-Based • Hybrid Approach • Academic Research\n")

# Required packages
required_packages <- c(
  "recommenderlab", "Matrix", "dplyr", "text", "tm", "cosine", 
  "cluster", "jsonlite", "digest", "stringr", "lubridate"
)

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("⚠️ Package", pkg, "not available, using fallbacks\n")
  } else {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
}

# RECOMMENDATION ENGINE CONFIGURATION
# ====================================

REC_CONFIG <- list(
  # Algorithm settings
  algorithms = list(
    collaborative_filtering = list(
      enabled = TRUE,
      method = "UBCF",  # User-Based Collaborative Filtering
      similarity = "cosine",
      neighborhood_size = 20,
      min_ratings = 3
    ),
    content_based = list(
      enabled = TRUE,
      similarity_method = "cosine",
      feature_weight = list(
        title = 0.4,
        abstract = 0.3,
        keywords = 0.2,
        metadata = 0.1
      ),
      min_similarity = 0.1
    ),
    hybrid = list(
      enabled = TRUE,
      collaborative_weight = 0.6,
      content_weight = 0.4,
      boost_new_items = TRUE
    )
  ),
  
  # User behavior tracking
  user_behavior = list(
    track_views = TRUE,
    track_downloads = TRUE,
    track_citations = TRUE,
    track_searches = TRUE,
    implicit_feedback_weight = 0.3,
    explicit_feedback_weight = 0.7,
    session_timeout_minutes = 30
  ),
  
  # Recommendation parameters
  recommendations = list(
    default_count = 10,
    max_count = 50,
    diversity_factor = 0.2,  # Balance between accuracy and diversity
    novelty_bonus = 0.1,     # Boost for newer documents
    recency_decay_days = 365, # How quickly old interactions lose weight
    min_confidence = 0.1
  ),
  
  # Academic features
  academic = list(
    citation_network_enabled = TRUE,
    author_collaboration_enabled = TRUE,
    institutional_affiliation_enabled = TRUE,
    research_area_matching = TRUE,
    paper_venue_similarity = TRUE
  ),
  
  # Performance settings
  performance = list(
    cache_enabled = TRUE,
    cache_ttl_hours = 6,
    batch_update_size = 100,
    parallel_processing = TRUE,
    memory_efficient_mode = TRUE
  )
)

# DATA STRUCTURES
# ===============

# User-item interaction matrix
user_interactions <- new.env()
user_interactions$matrix <- NULL
user_interactions$users <- character()
user_interactions$items <- character()
user_interactions$last_updated <- Sys.time()

# Document features matrix
document_features <- new.env()
document_features$tfidf_matrix <- NULL
document_features$feature_names <- character()
document_features$document_ids <- character()
document_features$last_updated <- Sys.time()

# User profiles
user_profiles <- new.env()

# Recommendation cache
recommendation_cache <- new.env()

# USER BEHAVIOR TRACKING
# =======================

# Record user interaction
record_user_interaction <- function(user_id, document_id, interaction_type = "view", 
                                  rating = NULL, context = list()) {
  tryCatch({
    cat("📝 Recording interaction:", user_id, "->", document_id, "(", interaction_type, ")\n")
    
    # Create interaction record
    interaction <- list(
      user_id = user_id,
      document_id = document_id,
      interaction_type = interaction_type,
      rating = rating,
      timestamp = Sys.time(),
      context = context
    )
    
    # Store in user profile
    profile_key <- paste0("profile_", user_id)
    
    if (!exists(profile_key, envir = user_profiles)) {
      # Create new user profile
      user_profile <- list(
        user_id = user_id,
        interactions = list(),
        preferences = list(),
        created_at = Sys.time(),
        last_active = Sys.time()
      )
      assign(profile_key, user_profile, envir = user_profiles)
    }
    
    # Update existing profile
    profile <- get(profile_key, envir = user_profiles)
    profile$interactions[[length(profile$interactions) + 1]] <- interaction
    profile$last_active <- Sys.time()
    
    # Update preferences based on interaction
    profile <- update_user_preferences(profile, interaction)
    
    assign(profile_key, profile, envir = user_profiles)
    
    # Update interaction matrix
    update_interaction_matrix(user_id, document_id, interaction_type, rating)
    
    # Clear related recommendation caches
    clear_user_cache(user_id)
    
    cat("✅ Interaction recorded successfully\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error recording interaction:", e$message, "\n")
    return(FALSE)
  })
}

# Update user preferences
update_user_preferences <- function(user_profile, interaction) {
  tryCatch({
    # Initialize preferences if not exist
    if (is.null(user_profile$preferences)) {
      user_profile$preferences <- list(
        topics = list(),
        agencies = list(),
        document_types = list(),
        states = list(),
        time_periods = list()
      )
    }
    
    # Get document metadata (in real implementation, fetch from database)
    doc_metadata <- get_document_metadata(interaction$document_id)
    
    if (!is.null(doc_metadata)) {
      # Update topic preferences
      if (!is.null(doc_metadata$topics)) {
        for (topic in doc_metadata$topics) {
          if (topic %in% names(user_profile$preferences$topics)) {
            user_profile$preferences$topics[[topic]] <- user_profile$preferences$topics[[topic]] + 1
          } else {
            user_profile$preferences$topics[[topic]] <- 1
          }
        }
      }
      
      # Update agency preferences
      if (!is.null(doc_metadata$agencies)) {
        for (agency in doc_metadata$agencies) {
          if (agency %in% names(user_profile$preferences$agencies)) {
            user_profile$preferences$agencies[[agency]] <- user_profile$preferences$agencies[[agency]] + 1
          } else {
            user_profile$preferences$agencies[[agency]] <- 1
          }
        }
      }
      
      # Update document type preferences
      if (!is.null(doc_metadata$species)) {
        type <- doc_metadata$species
        if (type %in% names(user_profile$preferences$document_types)) {
          user_profile$preferences$document_types[[type]] <- user_profile$preferences$document_types[[type]] + 1
        } else {
          user_profile$preferences$document_types[[type]] <- 1
        }
      }
    }
    
    return(user_profile)
    
  }, error = function(e) {
    cat("❌ Error updating user preferences:", e$message, "\n")
    return(user_profile)
  })
}

# Get document metadata (mock implementation)
get_document_metadata <- function(document_id) {
  # In real implementation, this would query the database
  # For now, return mock metadata
  mock_metadata <- list(
    id = document_id,
    topics = sample(c("Transporte Rodoviário", "Aviação Civil", "Transporte Aquaviário"), 
                   sample(1:3, 1)),
    agencies = sample(c("ANTT", "ANAC", "ANTAQ"), sample(1:2, 1)),
    species = sample(c("Lei", "Decreto", "Resolução", "Portaria"), 1),
    estado = sample(c("SP", "RJ", "MG", "RS", "PR"), 1),
    data_publicacao = Sys.Date() - sample(1:3650, 1)
  )
  
  return(mock_metadata)
}

# Update interaction matrix
update_interaction_matrix <- function(user_id, document_id, interaction_type, rating) {
  tryCatch({
    # Convert interaction to numeric rating
    numeric_rating <- convert_interaction_to_rating(interaction_type, rating)
    
    # Initialize matrix if needed
    if (is.null(user_interactions$matrix)) {
      user_interactions$matrix <- Matrix(0, nrow = 0, ncol = 0, sparse = TRUE)
      user_interactions$users <- character()
      user_interactions$items <- character()
    }
    
    # Add user/item if not exists
    if (!user_id %in% user_interactions$users) {
      user_interactions$users <- c(user_interactions$users, user_id)
      # Expand matrix
      if (length(user_interactions$items) > 0) {
        new_row <- Matrix(0, nrow = 1, ncol = length(user_interactions$items), sparse = TRUE)
        user_interactions$matrix <- rbind(user_interactions$matrix, new_row)
      }
    }
    
    if (!document_id %in% user_interactions$items) {
      user_interactions$items <- c(user_interactions$items, document_id)
      # Expand matrix
      if (length(user_interactions$users) > 0) {
        new_col <- Matrix(0, nrow = length(user_interactions$users), ncol = 1, sparse = TRUE)
        user_interactions$matrix <- cbind(user_interactions$matrix, new_col)
      }
    }
    
    # Initialize matrix if empty
    if (isTRUE(nrow(user_interactions$matrix) == 0) || ncol(user_interactions$matrix) == 0) {
      user_interactions$matrix <- Matrix(0, 
                                       nrow = length(user_interactions$users), 
                                       ncol = length(user_interactions$items), 
                                       sparse = TRUE)
    }
    
    # Update rating
    user_idx <- which(user_interactions$users == user_id)
    item_idx <- which(user_interactions$items == document_id)
    
    if (isTRUE(length(user_idx) > 0) && length(item_idx) > 0) {
      # Combine with existing rating if any
      existing_rating <- user_interactions$matrix[user_idx, item_idx]
      combined_rating <- max(existing_rating, numeric_rating)
      user_interactions$matrix[user_idx, item_idx] <- combined_rating
    }
    
    user_interactions$last_updated <- Sys.time()
    
  }, error = function(e) {
    cat("❌ Error updating interaction matrix:", e$message, "\n")
  })
}

# Convert interaction type to numeric rating
convert_interaction_to_rating <- function(interaction_type, rating = NULL) {
  if (!is.null(rating)) {
    return(as.numeric(rating))
  }
  
  # Implicit rating based on interaction type
  interaction_weights <- list(
    "view" = 1,
    "download" = 3,
    "bookmark" = 4,
    "cite" = 5,
    "share" = 3,
    "comment" = 4,
    "rate" = 5
  )
  
  return(interaction_weights[[interaction_type]] %||% 1)
}

# COLLABORATIVE FILTERING
# ========================

# Generate collaborative filtering recommendations
generate_collaborative_recommendations <- function(user_id, n_recommendations = REC_CONFIG$recommendations$default_count) {
  tryCatch({
    cat("🤝 Generating collaborative filtering recommendations for user:", user_id, "\n")
    
    # Check if we have enough data
    if (isTRUE(is.null(user_interactions$matrix)) || nrow(user_interactions$matrix) < 2) {
      return(list(error = "Insufficient interaction data for collaborative filtering"))
    }
    
    # Find user index
    user_idx <- which(user_interactions$users == user_id)
    if (length(user_idx) == 0) {
      return(list(error = "User not found in interaction matrix"))
    }
    
    # Get user's interaction vector
    user_vector <- user_interactions$matrix[user_idx, ]
    
    # Calculate user similarities
    similarities <- numeric()
    for (i in 1:nrow(user_interactions$matrix)) {
      if (i != user_idx) {
        other_vector <- user_interactions$matrix[i, ]
        # Calculate cosine similarity
        similarity <- calculate_cosine_similarity(user_vector, other_vector)
        similarities <- c(similarities, similarity)
      } else {
        similarities <- c(similarities, 0)  # Self similarity is 0 for recommendation purposes
      }
    }
    
    # Find similar users
    similar_users <- order(similarities, decreasing = TRUE)[1:min(REC_CONFIG$algorithms$collaborative_filtering$neighborhood_size, 
                                                                  length(similarities))]
    similar_users <- similar_users[similarities[similar_users] > 0]
    
    if (length(similar_users) == 0) {
      return(list(error = "No similar users found"))
    }
    
    # Get recommendations from similar users
    user_items <- which(user_vector > 0)  # Items user has already interacted with
    recommendations <- list()
    
    for (item_idx in 1:ncol(user_interactions$matrix)) {
      if (!item_idx %in% user_items) {  # User hasn't interacted with this item
        score <- 0
        total_similarity <- 0
        
        for (similar_user_idx in similar_users) {
          if (user_interactions$matrix[similar_user_idx, item_idx] > 0) {
            similarity <- similarities[similar_user_idx]
            rating <- user_interactions$matrix[similar_user_idx, item_idx]
            score <- score + similarity * rating
            total_similarity <- total_similarity + similarity
          }
        }
        
        if (total_similarity > 0) {
          final_score <- score / total_similarity
          recommendations[[length(recommendations) + 1]] <- list(
            document_id = user_interactions$items[item_idx],
            score = final_score,
            method = "collaborative_filtering"
          )
        }
      }
    }
    
    # Sort by score and return top N
    if (length(recommendations) > 0) {
      scores <- sapply(recommendations, function(x) x$score)
      top_indices <- order(scores, decreasing = TRUE)[1:min(n_recommendations, length(recommendations))]
      top_recommendations <- recommendations[top_indices]
      
      cat("✅ Generated", length(top_recommendations), "collaborative recommendations\n")
      return(top_recommendations)
    } else {
      return(list(error = "No recommendations could be generated"))
    }
    
  }, error = function(e) {
    cat("❌ Collaborative filtering error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Calculate cosine similarity between two vectors
calculate_cosine_similarity <- function(vec1, vec2) {
  tryCatch({
    if (requireNamespace("cosine", quietly = TRUE)) {
      return(cosine(as.numeric(vec1), as.numeric(vec2)))
    } else {
      # Manual cosine similarity calculation
      dot_product <- sum(vec1 * vec2)
      norm_vec1 <- sqrt(sum(vec1^2))
      norm_vec2 <- sqrt(sum(vec2^2))
      
      if (norm_vec1 == 0 || norm_vec2 == 0) {
        return(0)
      }
      
      return(dot_product / (norm_vec1 * norm_vec2))
    }
  }, error = function(e) {
    return(0)
  })
}

# CONTENT-BASED FILTERING
# ========================

# Build document feature matrix
build_document_features <- function(documents) {
  tryCatch({
    cat("📚 Building document feature matrix for", length(documents), "documents...\n")
    
    # Convert documents to data frame if needed
    if (is.list(documents) && !is.data.frame(documents)) {
      df <- do.call(rbind, lapply(documents, function(doc) {
        data.frame(
          id = doc$id %||% digest(doc$titulo %||% "unknown"),
          titulo = doc$titulo %||% "",
          ementa = doc$ementa %||% "",
          texto = doc$texto %||% "",
          species = doc$species %||% "",
          estado = doc$estado %||% "",
          stringsAsFactors = FALSE
        )
      }))
    } else {
      df <- documents
    }
    
    # Combine text fields
    df$combined_text <- paste(df$titulo, df$ementa, df$texto, sep = " ")
    
    # Text preprocessing
    processed_texts <- lapply(df$combined_text, function(text) {
      # Load AI services for text preprocessing if available
      if (file.exists("R/ai/ai_services.R") && exists("preprocess_portuguese_text")) {
        return(preprocess_portuguese_text(text))
      } else {
        # Basic preprocessing
        text <- tolower(text)
        text <- gsub("[[:punct:][:digit:]]", " ", text)
        text <- gsub("\\s+", " ", text)
        return(trimws(text))
      }
    })
    
    # Create TF-IDF matrix
    if (requireNamespace("tm", quietly = TRUE)) {
      corpus <- Corpus(VectorSource(processed_texts))
      dtm <- DocumentTermMatrix(corpus, control = list(
        weighting = weightTfIdf,
        minWordLength = 3,
        maxWordLength = 20,
        removeNumbers = TRUE,
        removePunctuation = TRUE
      ))
      
      # Convert to matrix
      tfidf_matrix <- as.matrix(dtm)
      feature_names <- colnames(tfidf_matrix)
      
    } else {
      # Fallback: simple word count matrix
      all_words <- unique(unlist(strsplit(unlist(processed_texts), " ")))
      all_words <- all_words[nchar(all_words) > 2]
      
      tfidf_matrix <- matrix(0, nrow = nrow(df), ncol = length(all_words))
      colnames(tfidf_matrix) <- all_words
      
      for (i in 1:nrow(df)) {
        doc_words <- unlist(strsplit(processed_texts[[i]], " "))
        for (word in doc_words) {
          if (word %in% all_words) {
            tfidf_matrix[i, word] <- tfidf_matrix[i, word] + 1
          }
        }
      }
      
      feature_names <- all_words
    }
    
    # Store in environment
    document_features$tfidf_matrix <- tfidf_matrix
    document_features$feature_names <- feature_names
    document_features$document_ids <- df$id
    document_features$last_updated <- Sys.time()
    
    cat("✅ Document feature matrix built:", nrow(tfidf_matrix), "documents x", ncol(tfidf_matrix), "features\n")
    
    return(list(
      matrix = tfidf_matrix,
      feature_names = feature_names,
      document_ids = df$id,
      success = TRUE
    ))
    
  }, error = function(e) {
    cat("❌ Error building document features:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Generate content-based recommendations
generate_content_recommendations <- function(user_id, n_recommendations = REC_CONFIG$recommendations$default_count) {
  tryCatch({
    cat("📖 Generating content-based recommendations for user:", user_id, "\n")
    
    # Check if feature matrix exists
    if (is.null(document_features$tfidf_matrix)) {
      return(list(error = "Document feature matrix not available"))
    }
    
    # Get user profile
    profile_key <- paste0("profile_", user_id)
    if (!exists(profile_key, envir = user_profiles)) {
      return(list(error = "User profile not found"))
    }
    
    user_profile <- get(profile_key, envir = user_profiles)
    
    # Get documents user has interacted with
    user_documents <- sapply(user_profile$interactions, function(x) x$document_id)
    
    if (length(user_documents) == 0) {
      return(list(error = "No user interaction history available"))
    }
    
    # Find indices of user documents in feature matrix
    user_doc_indices <- which(document_features$document_ids %in% user_documents)
    
    if (length(user_doc_indices) == 0) {
      return(list(error = "User documents not found in feature matrix"))
    }
    
    # Create user preference vector by averaging features of interacted documents
    user_preference_vector <- colMeans(document_features$tfidf_matrix[user_doc_indices, , drop = FALSE])
    
    # Calculate similarities to all documents
    similarities <- numeric(nrow(document_features$tfidf_matrix))
    
    for (i in 1:nrow(document_features$tfidf_matrix)) {
      doc_vector <- document_features$tfidf_matrix[i, ]
      similarity <- calculate_cosine_similarity(user_preference_vector, doc_vector)
      similarities[i] <- similarity
    }
    
    # Remove documents user has already interacted with
    available_docs <- setdiff(1:length(similarities), user_doc_indices)
    
    if (length(available_docs) == 0) {
      return(list(error = "No new documents available for recommendation"))
    }
    
    # Get top similar documents
    available_similarities <- similarities[available_docs]
    top_indices <- order(available_similarities, decreasing = TRUE)[1:min(n_recommendations, length(available_docs))]
    
    # Filter by minimum similarity threshold
    min_similarity <- REC_CONFIG$algorithms$content_based$min_similarity
    valid_indices <- top_indices[available_similarities[top_indices] >= min_similarity]
    
    if (length(valid_indices) == 0) {
      return(list(error = "No documents meet minimum similarity threshold"))
    }
    
    # Create recommendations
    recommendations <- lapply(valid_indices, function(idx) {
      doc_idx <- available_docs[idx]
      list(
        document_id = document_features$document_ids[doc_idx],
        score = available_similarities[idx],
        method = "content_based"
      )
    })
    
    cat("✅ Generated", length(recommendations), "content-based recommendations\n")
    return(recommendations)
    
  }, error = function(e) {
    cat("❌ Content-based filtering error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# HYBRID RECOMMENDATIONS
# ======================

# Generate hybrid recommendations
generate_hybrid_recommendations <- function(user_id, n_recommendations = REC_CONFIG$recommendations$default_count) {
  tryCatch({
    cat("🔀 Generating hybrid recommendations for user:", user_id, "\n")
    
    # Get collaborative filtering recommendations
    collaborative_recs <- generate_collaborative_recommendations(user_id, n_recommendations * 2)
    
    # Get content-based recommendations
    content_recs <- generate_content_recommendations(user_id, n_recommendations * 2)
    
    # Check if we have recommendations from both methods
    has_collaborative <- !("error" %in% names(collaborative_recs))
    has_content <- !("error" %in% names(content_recs))
    
    if (!has_collaborative && !has_content) {
      return(list(error = "Neither collaborative nor content-based recommendations available"))
    }
    
    hybrid_recs <- list()
    
    # Combine recommendations with weights
    collab_weight <- REC_CONFIG$algorithms$hybrid$collaborative_weight
    content_weight <- REC_CONFIG$algorithms$hybrid$content_weight
    
    # Create document score map
    doc_scores <- list()
    
    # Add collaborative scores
    if (has_collaborative) {
      for (rec in collaborative_recs) {
        doc_id <- rec$document_id
        score <- rec$score * collab_weight
        doc_scores[[doc_id]] <- list(
          total_score = score,
          collaborative_score = rec$score,
          content_score = 0,
          methods = "collaborative"
        )
      }
    }
    
    # Add content-based scores
    if (has_content) {
      for (rec in content_recs) {
        doc_id <- rec$document_id
        score <- rec$score * content_weight
        
        if (doc_id %in% names(doc_scores)) {
          # Document already has collaborative score
          doc_scores[[doc_id]]$total_score <- doc_scores[[doc_id]]$total_score + score
          doc_scores[[doc_id]]$content_score <- rec$score
          doc_scores[[doc_id]]$methods <- "hybrid"
        } else {
          # New document from content-based only
          doc_scores[[doc_id]] <- list(
            total_score = score,
            collaborative_score = 0,
            content_score = rec$score,
            methods = "content"
          )
        }
      }
    }
    
    # Convert to list and sort by total score
    final_recommendations <- list()
    
    for (doc_id in names(doc_scores)) {
      final_recommendations[[length(final_recommendations) + 1]] <- list(
        document_id = doc_id,
        score = doc_scores[[doc_id]]$total_score,
        collaborative_score = doc_scores[[doc_id]]$collaborative_score,
        content_score = doc_scores[[doc_id]]$content_score,
        method = "hybrid",
        component_methods = doc_scores[[doc_id]]$methods
      )
    }
    
    # Sort by score
    scores <- sapply(final_recommendations, function(x) x$score)
    sorted_indices <- order(scores, decreasing = TRUE)
    final_recommendations <- final_recommendations[sorted_indices]
    
    # Apply diversity and novelty adjustments
    final_recommendations <- apply_diversity_and_novelty(final_recommendations, user_id)
    
    # Return top N recommendations
    top_recommendations <- final_recommendations[1:min(n_recommendations, length(final_recommendations))]
    
    cat("✅ Generated", length(top_recommendations), "hybrid recommendations\n")
    return(top_recommendations)
    
  }, error = function(e) {
    cat("❌ Hybrid recommendation error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Apply diversity and novelty adjustments
apply_diversity_and_novelty <- function(recommendations, user_id) {
  tryCatch({
    # Get user profile for novelty calculation
    profile_key <- paste0("profile_", user_id)
    if (exists(profile_key, envir = user_profiles)) {
      user_profile <- get(profile_key, envir = user_profiles)
    } else {
      return(recommendations)
    }
    
    # Apply novelty bonus for newer documents
    if (REC_CONFIG$algorithms$hybrid$boost_new_items) {
      novelty_bonus <- REC_CONFIG$recommendations$novelty_bonus
      
      for (i in seq_along(recommendations)) {
        doc_metadata <- get_document_metadata(recommendations[[i]]$document_id)
        
        if (!is.null(doc_metadata$data_publicacao)) {
          days_old <- as.numeric(Sys.Date() - as.Date(doc_metadata$data_publicacao))
          decay_factor <- exp(-days_old / REC_CONFIG$recommendations$recency_decay_days)
          novelty_adjustment <- novelty_bonus * decay_factor
          
          recommendations[[i]]$score <- recommendations[[i]]$score + novelty_adjustment
          recommendations[[i]]$novelty_adjustment <- novelty_adjustment
        }
      }
    }
    
    # Re-sort after novelty adjustment
    scores <- sapply(recommendations, function(x) x$score)
    sorted_indices <- order(scores, decreasing = TRUE)
    recommendations <- recommendations[sorted_indices]
    
    return(recommendations)
    
  }, error = function(e) {
    cat("❌ Error applying diversity and novelty:", e$message, "\n")
    return(recommendations)
  })
}

# ACADEMIC RESEARCH FEATURES
# ===========================

# Generate research-focused recommendations
generate_research_recommendations <- function(user_id, research_context = list()) {
  tryCatch({
    cat("🎓 Generating research-focused recommendations...\n")
    
    # Get base hybrid recommendations
    base_recs <- generate_hybrid_recommendations(user_id, REC_CONFIG$recommendations$default_count * 2)
    
    if ("error" %in% names(base_recs)) {
      return(base_recs)
    }
    
    # Academic context adjustments
    research_recs <- base_recs
    
    # Citation network recommendations
    if (REC_CONFIG$academic$citation_network_enabled) {
      citation_boost <- 0.2
      
      for (i in seq_along(research_recs)) {
        doc_id <- research_recs[[i]]$document_id
        
        # Check if document is frequently cited (mock implementation)
        citation_score <- sample(c(0, 0.1, 0.2, 0.3), 1, prob = c(0.5, 0.3, 0.15, 0.05))
        
        research_recs[[i]]$score <- research_recs[[i]]$score + citation_score * citation_boost
        research_recs[[i]]$citation_boost <- citation_score * citation_boost
      }
    }
    
    # Research area matching
    if (REC_CONFIG$academic$research_area_matching && !is.null(research_context$research_areas)) {
      area_boost <- 0.15
      
      for (i in seq_along(research_recs)) {
        doc_metadata <- get_document_metadata(research_recs[[i]]$document_id)
        
        if (!is.null(doc_metadata$topics)) {
          topic_match <- length(intersect(doc_metadata$topics, research_context$research_areas))
          if (topic_match > 0) {
            boost_value <- (topic_match / length(research_context$research_areas)) * area_boost
            research_recs[[i]]$score <- research_recs[[i]]$score + boost_value
            research_recs[[i]]$research_area_boost <- boost_value
          }
        }
      }
    }
    
    # Institutional affiliation boost
    if (REC_CONFIG$academic$institutional_affiliation_enabled && !is.null(research_context$institution)) {
      institution_boost <- 0.1
      
      # Mock implementation - boost documents from same or collaborating institutions
      for (i in seq_along(research_recs)) {
        # Random institutional match for demonstration
        if (sample(c(TRUE, FALSE), 1, prob = c(0.1, 0.9))) {
          research_recs[[i]]$score <- research_recs[[i]]$score + institution_boost
          research_recs[[i]]$institutional_boost <- institution_boost
        }
      }
    }
    
    # Re-sort after academic adjustments
    scores <- sapply(research_recs, function(x) x$score)
    sorted_indices <- order(scores, decreasing = TRUE)
    research_recs <- research_recs[sorted_indices]
    
    # Add academic metadata
    for (i in seq_along(research_recs)) {
      research_recs[[i]]$academic_features <- list(
        citation_network_considered = REC_CONFIG$academic$citation_network_enabled,
        research_area_matching = !is.null(research_context$research_areas),
        institutional_context = !is.null(research_context$institution)
      )
    }
    
    cat("✅ Generated research-focused recommendations with academic enhancements\n")
    return(research_recs)
    
  }, error = function(e) {
    cat("❌ Research recommendation error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# CACHING AND PERFORMANCE
# ========================

# Cache recommendations
cache_recommendations <- function(user_id, recommendations, cache_type = "general") {
  if (!REC_CONFIG$performance$cache_enabled) return(FALSE)
  
  cache_key <- paste0("rec_", user_id, "_", cache_type)
  cache_item <- list(
    recommendations = recommendations,
    timestamp = Sys.time(),
    cache_type = cache_type
  )
  
  assign(cache_key, cache_item, envir = recommendation_cache)
  return(TRUE)
}

# Get cached recommendations
get_cached_recommendations <- function(user_id, cache_type = "general") {
  if (!REC_CONFIG$performance$cache_enabled) return(NULL)
  
  cache_key <- paste0("rec_", user_id, "_", cache_type)
  
  if (exists(cache_key, envir = recommendation_cache)) {
    cache_item <- get(cache_key, envir = recommendation_cache)
    
    # Check if cache is still valid
    cache_age_hours <- as.numeric(difftime(Sys.time(), cache_item$timestamp, units = "hours"))
    
    if (cache_age_hours < REC_CONFIG$performance$cache_ttl_hours) {
      cat("💾 Using cached recommendations\n")
      return(cache_item$recommendations)
    } else {
      # Remove expired cache
      rm(list = cache_key, envir = recommendation_cache)
    }
  }
  
  return(NULL)
}

# Clear user cache
clear_user_cache <- function(user_id) {
  cache_keys <- ls(envir = recommendation_cache)
  user_cache_keys <- cache_keys[grepl(paste0("rec_", user_id), cache_keys)]
  
  if (length(user_cache_keys) > 0) {
    rm(list = user_cache_keys, envir = recommendation_cache)
    cat("🗑️ Cleared cache for user:", user_id, "\n")
  }
}

# MAIN RECOMMENDATION INTERFACE
# ==============================

# Generate recommendations (main interface)
generate_recommendations <- function(user_id, 
                                   algorithm = "hybrid", 
                                   n_recommendations = REC_CONFIG$recommendations$default_count,
                                   research_context = NULL,
                                   force_refresh = FALSE) {
  tryCatch({
    cat("🎯 Generating recommendations for user:", user_id, "\n")
    cat("📊 Algorithm:", algorithm, "| Count:", n_recommendations, "\n")
    
    # Check cache first (unless force refresh)
    if (!force_refresh) {
      cached_recs <- get_cached_recommendations(user_id, algorithm)
      if (!is.null(cached_recs)) {
        return(cached_recs[1:min(n_recommendations, length(cached_recs))])
      }
    }
    
    # Generate recommendations based on algorithm
    if (algorithm == "collaborative") {
      recommendations <- generate_collaborative_recommendations(user_id, n_recommendations)
    } else if (algorithm == "content") {
      recommendations <- generate_content_recommendations(user_id, n_recommendations)
    } else if (algorithm == "hybrid") {
      recommendations <- generate_hybrid_recommendations(user_id, n_recommendations)
    } else if (algorithm == "research") {
      recommendations <- generate_research_recommendations(user_id, research_context %||% list())
    } else {
      return(list(error = "Unknown algorithm specified"))
    }
    
    # Check for errors
    if ("error" %in% names(recommendations)) {
      return(recommendations)
    }
    
    # Add metadata
    for (i in seq_along(recommendations)) {
      recommendations[[i]]$generated_at <- Sys.time()
      recommendations[[i]]$algorithm_used <- algorithm
      recommendations[[i]]$rank <- i
    }
    
    # Cache results
    cache_recommendations(user_id, recommendations, algorithm)
    
    # Return requested number of recommendations
    final_recs <- recommendations[1:min(n_recommendations, length(recommendations))]
    
    cat("✅ Generated", length(final_recs), "recommendations using", algorithm, "algorithm\n")
    
    return(list(
      recommendations = final_recs,
      metadata = list(
        user_id = user_id,
        algorithm = algorithm,
        total_generated = length(recommendations),
        returned_count = length(final_recs),
        generated_at = Sys.time(),
        cache_used = !force_refresh
      )
    ))
    
  }, error = function(e) {
    cat("❌ Recommendation generation error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# GET RECOMMENDATION STATISTICS
# =============================

# Get recommendation system statistics
get_recommendation_stats <- function() {
  tryCatch({
    stats <- list(
      system_info = list(
        algorithms_enabled = names(REC_CONFIG$algorithms)[sapply(REC_CONFIG$algorithms, function(x) x$enabled)],
        cache_enabled = REC_CONFIG$performance$cache_enabled,
        academic_features_enabled = any(unlist(REC_CONFIG$academic))
      ),
      
      user_data = list(
        total_users = length(ls(envir = user_profiles)),
        total_interactions = if (!is.null(user_interactions$matrix)) sum(user_interactions$matrix > 0) else 0,
        matrix_dimensions = if (!is.null(user_interactions$matrix)) dim(user_interactions$matrix) else c(0, 0)
      ),
      
      document_data = list(
        total_documents = length(document_features$document_ids),
        feature_dimensions = if (!is.null(document_features$tfidf_matrix)) dim(document_features$tfidf_matrix) else c(0, 0),
        last_feature_update = document_features$last_updated
      ),
      
      cache_data = list(
        cached_recommendations = length(ls(envir = recommendation_cache)),
        cache_ttl_hours = REC_CONFIG$performance$cache_ttl_hours
      ),
      
      performance = list(
        memory_efficient_mode = REC_CONFIG$performance$memory_efficient_mode,
        parallel_processing = REC_CONFIG$performance$parallel_processing,
        batch_update_size = REC_CONFIG$performance$batch_update_size
      )
    )
    
    return(stats)
    
  }, error = function(e) {
    cat("❌ Error getting recommendation stats:", e$message, "\n")
    return(list(error = e$message))
  })
}

# Initialize recommendation engine
init_recommendation_engine <- function() {
  cat("🎯 Initializing Recommendation Engine...\n")
  cat("🤝 Collaborative filtering enabled:", REC_CONFIG$algorithms$collaborative_filtering$enabled, "\n")
  cat("📖 Content-based filtering enabled:", REC_CONFIG$algorithms$content_based$enabled, "\n")
  cat("🔀 Hybrid approach enabled:", REC_CONFIG$algorithms$hybrid$enabled, "\n")
  cat("🎓 Academic features enabled:", any(unlist(REC_CONFIG$academic)), "\n")
  cat("💾 Caching enabled:", REC_CONFIG$performance$cache_enabled, "\n")
  cat("📊 Default recommendations:", REC_CONFIG$recommendations$default_count, "\n")
  
  return(TRUE)
}

# Export recommendation engine functions
REC_FUNCTIONS <- list(
  record_user_interaction = record_user_interaction,
  build_document_features = build_document_features,
  generate_recommendations = generate_recommendations,
  generate_collaborative_recommendations = generate_collaborative_recommendations,
  generate_content_recommendations = generate_content_recommendations,
  generate_hybrid_recommendations = generate_hybrid_recommendations,
  generate_research_recommendations = generate_research_recommendations,
  get_recommendation_stats = get_recommendation_stats,
  clear_user_cache = clear_user_cache,
  init_recommendation_engine = init_recommendation_engine
)

# Initialize on load
init_recommendation_engine()

cat("✅ Recommendation Engine ready for personalized legislative research assistance\n")