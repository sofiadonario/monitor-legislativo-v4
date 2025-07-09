# Recommendation Engine for Monitor Legislativo v4
# AI-powered content recommendations and personalized suggestions

library(dplyr)
library(jsonlite)
library(digest)
library(lubridate)
library(Matrix)

# Recommendation engine configuration
RECOMMENDATION_CONFIG <- list(
  algorithms = list(
    content_based = list(
      enabled = TRUE,
      weight = 0.4,
      similarity_threshold = 0.6,
      max_features = 1000
    ),
    
    collaborative_filtering = list(
      enabled = TRUE,
      weight = 0.3,
      min_interactions = 5,
      max_neighbors = 50
    ),
    
    popularity_based = list(
      enabled = TRUE,
      weight = 0.2,
      time_decay = 0.95,
      boost_trending = TRUE
    ),
    
    semantic_similarity = list(
      enabled = TRUE,
      weight = 0.1,
      use_embeddings = TRUE,
      similarity_threshold = 0.7
    )
  ),
  
  user_profiling = list(
    track_interactions = TRUE,
    interaction_types = c("view", "download", "share", "save", "search"),
    interaction_weights = list(
      view = 1.0,
      download = 2.0,
      share = 3.0,
      save = 2.5,
      search = 1.5
    ),
    profile_decay_days = 90,
    min_profile_interactions = 3
  ),
  
  recommendations = list(
    max_recommendations = 20,
    diversification_factor = 0.3,
    freshness_boost = 0.1,
    explanation_enabled = TRUE,
    real_time_updates = TRUE
  ),
  
  evaluation = list(
    track_performance = TRUE,
    metrics = c("precision", "recall", "diversity", "novelty"),
    evaluation_window_days = 30
  )
)

# Global recommendation state
recommendation_state <- list(
  user_profiles = list(),
  document_features = list(),
  interaction_matrix = NULL,
  popularity_scores = list(),
  recommendation_cache = list(),
  performance_metrics = list()
)

#' Initialize recommendation engine
#' @param config Optional configuration override
#' @return Initialization status
initialize_recommendation_engine <- function(config = NULL) {
  if (!is.null(config)) {
    RECOMMENDATION_CONFIG <<- modifyList(RECOMMENDATION_CONFIG, config)
  }
  
  log_event("Initializing recommendation engine...", "INFO")
  
  # Initialize state
  recommendation_state$user_profiles <<- list()
  recommendation_state$document_features <<- list()
  recommendation_state$interaction_matrix <<- NULL
  recommendation_state$popularity_scores <<- list()
  recommendation_state$recommendation_cache <<- list()
  recommendation_state$performance_metrics <<- list()
  
  # Load existing data if available
  load_recommendation_data()
  
  # Initialize document features
  initialize_document_features()
  
  log_event("Recommendation engine initialized successfully", "INFO")
  
  return(list(
    status = "success",
    algorithms_enabled = sum(sapply(RECOMMENDATION_CONFIG$algorithms, function(x) x$enabled)),
    user_profiles = length(recommendation_state$user_profiles),
    document_features = length(recommendation_state$document_features)
  ))
}

#' Record user interaction
#' @param user_id User identifier
#' @param document_id Document identifier
#' @param interaction_type Type of interaction
#' @param metadata Additional interaction metadata
record_user_interaction <- function(user_id, document_id, interaction_type, metadata = list()) {
  if (!RECOMMENDATION_CONFIG$user_profiling$track_interactions) {
    return()
  }
  
  log_event(paste("Recording interaction:", user_id, "->", document_id, "(", interaction_type, ")"), "INFO")
  
  # Initialize user profile if doesn't exist
  if (is.null(recommendation_state$user_profiles[[user_id]])) {
    recommendation_state$user_profiles[[user_id]] <<- list(
      user_id = user_id,
      interactions = list(),
      preferences = list(),
      created_at = Sys.time(),
      last_updated = Sys.time()
    )
  }
  
  # Add interaction
  interaction <- list(
    document_id = document_id,
    interaction_type = interaction_type,
    timestamp = Sys.time(),
    weight = RECOMMENDATION_CONFIG$user_profiling$interaction_weights[[interaction_type]] %||% 1.0,
    metadata = metadata
  )
  
  user_profile <- recommendation_state$user_profiles[[user_id]]
  user_profile$interactions <- append(user_profile$interactions, list(interaction))
  user_profile$last_updated <- Sys.time()
  
  recommendation_state$user_profiles[[user_id]] <<- user_profile
  
  # Update user preferences
  update_user_preferences(user_id)
  
  # Update popularity scores
  update_popularity_scores(document_id, interaction_type)
  
  # Clear recommendation cache for user
  clear_user_recommendation_cache(user_id)
}

#' Generate recommendations for user
#' @param user_id User identifier
#' @param exclude_seen Whether to exclude already seen documents
#' @param max_results Maximum number of recommendations
#' @return List of recommendations
generate_recommendations <- function(user_id, exclude_seen = TRUE, max_results = NULL) {
  max_results <- max_results %||% RECOMMENDATION_CONFIG$recommendations$max_recommendations
  
  log_event(paste("Generating recommendations for user:", user_id), "INFO")
  
  # Check cache first
  cache_key <- generate_recommendation_cache_key(user_id, exclude_seen, max_results)
  cached_recommendations <- get_cached_recommendations(cache_key)
  
  if (!is.null(cached_recommendations)) {
    log_event("Cache HIT for user recommendations", "INFO")
    return(cached_recommendations)
  }
  
  # Get user profile
  user_profile <- recommendation_state$user_profiles[[user_id]]
  
  if (is.null(user_profile) || length(user_profile$interactions) < RECOMMENDATION_CONFIG$user_profiling$min_profile_interactions) {
    # Fallback to popularity-based recommendations for new users
    recommendations <- generate_popularity_recommendations(max_results)
  } else {
    # Generate hybrid recommendations
    recommendations <- generate_hybrid_recommendations(user_id, exclude_seen, max_results)
  }
  
  # Apply diversification
  if (RECOMMENDATION_CONFIG$recommendations$diversification_factor > 0) {
    recommendations <- apply_diversification(recommendations, RECOMMENDATION_CONFIG$recommendations$diversification_factor)
  }
  
  # Add explanations if enabled
  if (RECOMMENDATION_CONFIG$recommendations$explanation_enabled) {
    recommendations <- add_recommendation_explanations(recommendations, user_id)
  }
  
  # Cache recommendations
  cache_recommendations(cache_key, recommendations)
  
  log_event(paste("Generated", length(recommendations), "recommendations for user:", user_id), "INFO")
  
  return(recommendations)
}

#' Generate hybrid recommendations
#' @param user_id User identifier
#' @param exclude_seen Whether to exclude seen documents
#' @param max_results Maximum results
#' @return Hybrid recommendations
generate_hybrid_recommendations <- function(user_id, exclude_seen, max_results) {
  algorithms <- RECOMMENDATION_CONFIG$algorithms
  all_recommendations <- list()
  
  # Content-based recommendations
  if (algorithms$content_based$enabled) {
    content_recs <- generate_content_based_recommendations(user_id, max_results)
    all_recommendations$content_based <- list(
      recommendations = content_recs,
      weight = algorithms$content_based$weight
    )
  }
  
  # Collaborative filtering recommendations
  if (algorithms$collaborative_filtering$enabled) {
    collab_recs <- generate_collaborative_recommendations(user_id, max_results)
    all_recommendations$collaborative <- list(
      recommendations = collab_recs,
      weight = algorithms$collaborative_filtering$weight
    )
  }
  
  # Popularity-based recommendations
  if (algorithms$popularity_based$enabled) {
    popularity_recs <- generate_popularity_recommendations(max_results)
    all_recommendations$popularity <- list(
      recommendations = popularity_recs,
      weight = algorithms$popularity_based$weight
    )
  }
  
  # Semantic similarity recommendations
  if (algorithms$semantic_similarity$enabled && algorithms$semantic_similarity$use_embeddings) {
    semantic_recs <- generate_semantic_recommendations(user_id, max_results)
    all_recommendations$semantic <- list(
      recommendations = semantic_recs,
      weight = algorithms$semantic_similarity$weight
    )
  }
  
  # Combine recommendations
  combined_recommendations <- combine_recommendation_lists(all_recommendations, max_results)
  
  # Filter out seen documents if requested
  if (exclude_seen) {
    combined_recommendations <- filter_seen_documents(combined_recommendations, user_id)
  }
  
  return(head(combined_recommendations, max_results))
}

#' Generate content-based recommendations
#' @param user_id User identifier
#' @param max_results Maximum results
#' @return Content-based recommendations
generate_content_based_recommendations <- function(user_id, max_results) {
  user_profile <- recommendation_state$user_profiles[[user_id]]
  
  if (is.null(user_profile) || is.null(user_profile$preferences)) {
    return(list())
  }
  
  user_preferences <- user_profile$preferences
  recommendations <- list()
  
  # Find documents similar to user's preferred content
  for (doc_id in names(recommendation_state$document_features)) {
    doc_features <- recommendation_state$document_features[[doc_id]]
    
    # Calculate content similarity
    similarity <- calculate_content_similarity(user_preferences, doc_features)
    
    if (similarity >= RECOMMENDATION_CONFIG$algorithms$content_based$similarity_threshold) {
      recommendation <- list(
        document_id = doc_id,
        score = similarity,
        algorithm = "content_based",
        features = doc_features
      )
      
      recommendations <- append(recommendations, list(recommendation))
    }
  }
  
  # Sort by score and return top results
  recommendations <- recommendations[order(sapply(recommendations, function(x) x$score), decreasing = TRUE)]
  
  return(head(recommendations, max_results))
}

#' Generate collaborative filtering recommendations
#' @param user_id User identifier
#' @param max_results Maximum results
#' @return Collaborative recommendations
generate_collaborative_recommendations <- function(user_id, max_results) {
  # Build user-item interaction matrix if not exists
  if (is.null(recommendation_state$interaction_matrix)) {
    build_interaction_matrix()
  }
  
  interaction_matrix <- recommendation_state$interaction_matrix
  
  if (is.null(interaction_matrix) || !user_id %in% rownames(interaction_matrix)) {
    return(list())
  }
  
  # Find similar users
  user_similarities <- calculate_user_similarities(user_id, interaction_matrix)
  
  # Get top similar users
  max_neighbors <- RECOMMENDATION_CONFIG$algorithms$collaborative_filtering$max_neighbors
  similar_users <- head(user_similarities[order(user_similarities$similarity, decreasing = TRUE), ], max_neighbors)
  
  # Generate recommendations based on similar users' preferences
  recommendations <- list()
  
  for (i in 1:nrow(similar_users)) {
    similar_user_id <- similar_users$user_id[i]
    similarity_score <- similar_users$similarity[i]
    
    # Get documents liked by similar user but not seen by target user
    similar_user_docs <- which(interaction_matrix[similar_user_id, ] > 0)
    target_user_docs <- which(interaction_matrix[user_id, ] > 0)
    
    candidate_docs <- setdiff(similar_user_docs, target_user_docs)
    
    for (doc_idx in candidate_docs) {
      doc_id <- colnames(interaction_matrix)[doc_idx]
      
      # Calculate recommendation score
      doc_score <- interaction_matrix[similar_user_id, doc_idx] * similarity_score
      
      # Find existing recommendation or create new one
      existing_rec <- Find(function(x) x$document_id == doc_id, recommendations)
      
      if (is.null(existing_rec)) {
        recommendation <- list(
          document_id = doc_id,
          score = doc_score,
          algorithm = "collaborative",
          similar_users = list(similar_user_id)
        )
        recommendations <- append(recommendations, list(recommendation))
      } else {
        # Update existing recommendation
        idx <- which(sapply(recommendations, function(x) x$document_id == doc_id))
        recommendations[[idx]]$score <- recommendations[[idx]]$score + doc_score
        recommendations[[idx]]$similar_users <- append(recommendations[[idx]]$similar_users, similar_user_id)
      }
    }
  }
  
  # Sort by score and return top results
  recommendations <- recommendations[order(sapply(recommendations, function(x) x$score), decreasing = TRUE)]
  
  return(head(recommendations, max_results))
}

#' Generate popularity-based recommendations
#' @param max_results Maximum results
#' @return Popularity recommendations
generate_popularity_recommendations <- function(max_results) {
  popularity_scores <- recommendation_state$popularity_scores
  
  if (length(popularity_scores) == 0) {
    return(list())
  }
  
  # Apply time decay to popularity scores
  current_time <- Sys.time()
  decay_rate <- RECOMMENDATION_CONFIG$algorithms$popularity_based$time_decay
  
  decayed_scores <- lapply(names(popularity_scores), function(doc_id) {
    score_data <- popularity_scores[[doc_id]]
    
    # Calculate time decay
    days_old <- as.numeric(current_time - score_data$last_updated, units = "days")
    decayed_score <- score_data$score * (decay_rate ^ days_old)
    
    list(
      document_id = doc_id,
      score = decayed_score,
      algorithm = "popularity",
      raw_score = score_data$score,
      last_updated = score_data$last_updated
    )
  })
  
  # Sort by decayed score
  decayed_scores <- decayed_scores[order(sapply(decayed_scores, function(x) x$score), decreasing = TRUE)]
  
  return(head(decayed_scores, max_results))
}

#' Generate semantic similarity recommendations
#' @param user_id User identifier
#' @param max_results Maximum results
#' @return Semantic recommendations
generate_semantic_recommendations <- function(user_id, max_results) {
  # Requires semantic search integration
  if (!exists("semantic_search_query")) {
    return(list())
  }
  
  user_profile <- recommendation_state$user_profiles[[user_id]]
  
  if (is.null(user_profile) || length(user_profile$interactions) == 0) {
    return(list())
  }
  
  # Build query from user's interaction history
  recent_interactions <- tail(user_profile$interactions, 10)
  query_terms <- c()
  
  for (interaction in recent_interactions) {
    # Get document content for query building
    doc_features <- recommendation_state$document_features[[interaction$document_id]]
    if (!is.null(doc_features$keywords)) {
      query_terms <- c(query_terms, doc_features$keywords)
    }
  }
  
  if (length(query_terms) == 0) {
    return(list())
  }
  
  # Create semantic query
  semantic_query <- paste(head(unique(query_terms), 10), collapse = " ")
  
  # Perform semantic search
  search_results <- semantic_search_query(
    query = semantic_query,
    options = list(
      similarity_threshold = RECOMMENDATION_CONFIG$algorithms$semantic_similarity$similarity_threshold,
      max_results = max_results
    )
  )
  
  # Convert search results to recommendations
  recommendations <- lapply(search_results$results, function(result) {
    list(
      document_id = result$document_id,
      score = result$similarity_score,
      algorithm = "semantic",
      query = semantic_query,
      similarity_score = result$similarity_score
    )
  })
  
  return(recommendations)
}

#' Update user preferences based on interactions
#' @param user_id User identifier
update_user_preferences <- function(user_id) {
  user_profile <- recommendation_state$user_profiles[[user_id]]
  
  if (is.null(user_profile) || length(user_profile$interactions) == 0) {
    return()
  }
  
  # Analyze user's interaction patterns
  preferences <- list(
    document_types = list(),
    states = list(),
    keywords = list(),
    interaction_patterns = list()
  )
  
  # Weight recent interactions more heavily
  cutoff_date <- Sys.time() - days(RECOMMENDATION_CONFIG$user_profiling$profile_decay_days)
  recent_interactions <- Filter(function(x) x$timestamp > cutoff_date, user_profile$interactions)
  
  for (interaction in recent_interactions) {
    doc_features <- recommendation_state$document_features[[interaction$document_id]]
    
    if (!is.null(doc_features)) {
      # Document type preferences
      if (!is.null(doc_features$type)) {
        type_key <- doc_features$type
        preferences$document_types[[type_key]] <- 
          (preferences$document_types[[type_key]] %||% 0) + interaction$weight
      }
      
      # State preferences
      if (!is.null(doc_features$state)) {
        state_key <- doc_features$state
        preferences$states[[state_key]] <- 
          (preferences$states[[state_key]] %||% 0) + interaction$weight
      }
      
      # Keyword preferences
      if (!is.null(doc_features$keywords)) {
        for (keyword in doc_features$keywords) {
          preferences$keywords[[keyword]] <- 
            (preferences$keywords[[keyword]] %||% 0) + interaction$weight
        }
      }
    }
    
    # Interaction pattern analysis
    pattern_key <- interaction$interaction_type
    preferences$interaction_patterns[[pattern_key]] <- 
      (preferences$interaction_patterns[[pattern_key]] %||% 0) + 1
  }
  
  # Normalize preferences
  preferences$document_types <- normalize_preferences(preferences$document_types)
  preferences$states <- normalize_preferences(preferences$states)
  preferences$keywords <- normalize_preferences(preferences$keywords)
  
  # Update user profile
  user_profile$preferences <- preferences
  recommendation_state$user_profiles[[user_id]] <<- user_profile
}

#' Initialize document features
initialize_document_features <- function() {
  # This would typically load from document database
  # For now, we'll create a placeholder structure
  
  log_event("Initializing document features for recommendation engine", "INFO")
  
  # Document features would include:
  # - Document type, state, keywords
  # - Content embeddings (if available)
  # - Metadata features
  # - Statistical features (views, downloads, etc.)
  
  return(list(status = "initialized"))
}

#' Calculate content similarity between user preferences and document
#' @param user_preferences User preference profile
#' @param doc_features Document features
#' @return Similarity score
calculate_content_similarity <- function(user_preferences, doc_features) {
  if (is.null(user_preferences) || is.null(doc_features)) {
    return(0)
  }
  
  similarity <- 0
  total_weight <- 0
  
  # Document type similarity
  if (!is.null(user_preferences$document_types) && !is.null(doc_features$type)) {
    type_pref <- user_preferences$document_types[[doc_features$type]] %||% 0
    similarity <- similarity + (type_pref * 0.3)
    total_weight <- total_weight + 0.3
  }
  
  # State similarity
  if (!is.null(user_preferences$states) && !is.null(doc_features$state)) {
    state_pref <- user_preferences$states[[doc_features$state]] %||% 0
    similarity <- similarity + (state_pref * 0.2)
    total_weight <- total_weight + 0.2
  }
  
  # Keyword similarity
  if (!is.null(user_preferences$keywords) && !is.null(doc_features$keywords)) {
    keyword_similarities <- sapply(doc_features$keywords, function(keyword) {
      user_preferences$keywords[[keyword]] %||% 0
    })
    
    avg_keyword_sim <- mean(keyword_similarities)
    similarity <- similarity + (avg_keyword_sim * 0.5)
    total_weight <- total_weight + 0.5
  }
  
  # Normalize by total weight
  if (total_weight > 0) {
    similarity <- similarity / total_weight
  }
  
  return(min(1, max(0, similarity)))
}

#' Build user-item interaction matrix
build_interaction_matrix <- function() {
  if (length(recommendation_state$user_profiles) == 0) {
    return()
  }
  
  # Collect all users and documents
  all_users <- names(recommendation_state$user_profiles)
  all_documents <- unique(unlist(lapply(recommendation_state$user_profiles, function(profile) {
    sapply(profile$interactions, function(interaction) interaction$document_id)
  })))
  
  if (length(all_documents) == 0) {
    return()
  }
  
  # Create matrix
  interaction_matrix <- Matrix(0, nrow = length(all_users), ncol = length(all_documents), 
                              dimnames = list(all_users, all_documents), sparse = TRUE)
  
  # Fill matrix with interaction scores
  for (user_id in all_users) {
    user_profile <- recommendation_state$user_profiles[[user_id]]
    
    for (interaction in user_profile$interactions) {
      doc_id <- interaction$document_id
      
      if (doc_id %in% all_documents) {
        current_score <- interaction_matrix[user_id, doc_id]
        interaction_matrix[user_id, doc_id] <- current_score + interaction$weight
      }
    }
  }
  
  recommendation_state$interaction_matrix <<- interaction_matrix
}

# Helper functions

#' Combine multiple recommendation lists
#' @param recommendation_lists List of recommendation lists with weights
#' @param max_results Maximum results to return
#' @return Combined recommendations
combine_recommendation_lists <- function(recommendation_lists, max_results) {
  if (length(recommendation_lists) == 0) {
    return(list())
  }
  
  # Collect all recommendations
  all_recommendations <- list()
  
  for (algorithm_name in names(recommendation_lists)) {
    algorithm_data <- recommendation_lists[[algorithm_name]]
    weight <- algorithm_data$weight
    
    for (rec in algorithm_data$recommendations) {
      doc_id <- rec$document_id
      
      # Find existing recommendation or create new one
      existing_idx <- which(sapply(all_recommendations, function(x) x$document_id == doc_id))
      
      if (length(existing_idx) == 0) {
        # New recommendation
        combined_rec <- list(
          document_id = doc_id,
          combined_score = rec$score * weight,
          algorithms = list(algorithm_name),
          algorithm_scores = list(),
          features = rec$features %||% list()
        )
        combined_rec$algorithm_scores[[algorithm_name]] <- rec$score
        
        all_recommendations <- append(all_recommendations, list(combined_rec))
      } else {
        # Update existing recommendation
        idx <- existing_idx[1]
        all_recommendations[[idx]]$combined_score <- 
          all_recommendations[[idx]]$combined_score + (rec$score * weight)
        all_recommendations[[idx]]$algorithms <- 
          append(all_recommendations[[idx]]$algorithms, algorithm_name)
        all_recommendations[[idx]]$algorithm_scores[[algorithm_name]] <- rec$score
      }
    }
  }
  
  # Sort by combined score
  all_recommendations <- all_recommendations[order(sapply(all_recommendations, function(x) x$combined_score), decreasing = TRUE)]
  
  return(head(all_recommendations, max_results))
}

#' Apply diversification to recommendations
#' @param recommendations List of recommendations
#' @param diversification_factor Factor for diversification (0-1)
#' @return Diversified recommendations
apply_diversification <- function(recommendations, diversification_factor) {
  if (length(recommendations) <= 1 || diversification_factor == 0) {
    return(recommendations)
  }
  
  # Simple diversification: ensure variety in document types and states
  diversified <- list()
  seen_types <- c()
  seen_states <- c()
  
  # First pass: add highest scored items ensuring diversity
  for (rec in recommendations) {
    doc_features <- recommendation_state$document_features[[rec$document_id]]
    
    doc_type <- doc_features$type %||% "unknown"
    doc_state <- doc_features$state %||% "unknown"
    
    # Check if we need more diversity
    type_penalty <- if (doc_type %in% seen_types) diversification_factor else 0
    state_penalty <- if (doc_state %in% seen_states) diversification_factor * 0.5 else 0
    
    # Apply diversity penalty
    diversity_score <- rec$combined_score * (1 - type_penalty - state_penalty)
    rec$diversity_score <- diversity_score
    
    diversified <- append(diversified, list(rec))
    seen_types <- c(seen_types, doc_type)
    seen_states <- c(seen_states, doc_state)
  }
  
  # Sort by diversity score
  diversified <- diversified[order(sapply(diversified, function(x) x$diversity_score), decreasing = TRUE)]
  
  return(diversified)
}

#' Add explanations to recommendations
#' @param recommendations List of recommendations
#' @param user_id User identifier
#' @return Recommendations with explanations
add_recommendation_explanations <- function(recommendations, user_id) {
  for (i in seq_along(recommendations)) {
    rec <- recommendations[[i]]
    
    explanation_parts <- c()
    
    # Algorithm-based explanations
    if ("content_based" %in% rec$algorithms) {
      explanation_parts <- c(explanation_parts, "similar to documents you've viewed")
    }
    
    if ("collaborative" %in% rec$algorithms) {
      explanation_parts <- c(explanation_parts, "liked by users with similar interests")
    }
    
    if ("popularity" %in% rec$algorithms) {
      explanation_parts <- c(explanation_parts, "popular among other users")
    }
    
    if ("semantic" %in% rec$algorithms) {
      explanation_parts <- c(explanation_parts, "semantically related to your interests")
    }
    
    # Create combined explanation
    if (length(explanation_parts) > 0) {
      rec$explanation <- paste("Recommended because it's", paste(explanation_parts, collapse = " and "))
    } else {
      rec$explanation <- "Recommended based on your activity"
    }
    
    recommendations[[i]] <- rec
  }
  
  return(recommendations)
}

#' Normalize preference scores
#' @param preferences Preference list
#' @return Normalized preferences
normalize_preferences <- function(preferences) {
  if (length(preferences) == 0) {
    return(preferences)
  }
  
  max_score <- max(unlist(preferences))
  
  if (max_score == 0) {
    return(preferences)
  }
  
  normalized <- lapply(preferences, function(score) score / max_score)
  
  return(normalized)
}

#' Update popularity scores
#' @param document_id Document identifier
#' @param interaction_type Type of interaction
update_popularity_scores <- function(document_id, interaction_type) {
  weight <- RECOMMENDATION_CONFIG$user_profiling$interaction_weights[[interaction_type]] %||% 1.0
  
  if (is.null(recommendation_state$popularity_scores[[document_id]])) {
    recommendation_state$popularity_scores[[document_id]] <<- list(
      score = weight,
      interaction_count = 1,
      last_updated = Sys.time()
    )
  } else {
    current_data <- recommendation_state$popularity_scores[[document_id]]
    current_data$score <- current_data$score + weight
    current_data$interaction_count <- current_data$interaction_count + 1
    current_data$last_updated <- Sys.time()
    
    recommendation_state$popularity_scores[[document_id]] <<- current_data
  }
}

#' Cache management functions
generate_recommendation_cache_key <- function(user_id, exclude_seen, max_results) {
  key_data <- list(user_id = user_id, exclude_seen = exclude_seen, max_results = max_results)
  digest(toJSON(key_data, auto_unbox = TRUE), algo = "md5")
}

cache_recommendations <- function(cache_key, recommendations) {
  recommendation_state$recommendation_cache[[cache_key]] <<- list(
    recommendations = recommendations,
    cached_at = Sys.time()
  )
}

get_cached_recommendations <- function(cache_key) {
  cache_entry <- recommendation_state$recommendation_cache[[cache_key]]
  
  if (is.null(cache_entry)) {
    return(NULL)
  }
  
  # Cache TTL of 1 hour
  age_hours <- as.numeric(Sys.time() - cache_entry$cached_at, units = "hours")
  if (age_hours > 1) {
    recommendation_state$recommendation_cache[[cache_key]] <<- NULL
    return(NULL)
  }
  
  return(cache_entry$recommendations)
}

clear_user_recommendation_cache <- function(user_id) {
  # Remove cached recommendations for specific user
  cache_keys_to_remove <- c()
  
  for (cache_key in names(recommendation_state$recommendation_cache)) {
    if (grepl(user_id, cache_key)) {
      cache_keys_to_remove <- c(cache_keys_to_remove, cache_key)
    }
  }
  
  for (key in cache_keys_to_remove) {
    recommendation_state$recommendation_cache[[key]] <<- NULL
  }
}

filter_seen_documents <- function(recommendations, user_id) {
  user_profile <- recommendation_state$user_profiles[[user_id]]
  
  if (is.null(user_profile)) {
    return(recommendations)
  }
  
  seen_documents <- unique(sapply(user_profile$interactions, function(x) x$document_id))
  
  filtered_recommendations <- Filter(function(rec) {
    !rec$document_id %in% seen_documents
  }, recommendations)
  
  return(filtered_recommendations)
}

calculate_user_similarities <- function(target_user_id, interaction_matrix) {
  if (!target_user_id %in% rownames(interaction_matrix)) {
    return(data.frame())
  }
  
  target_user_vector <- interaction_matrix[target_user_id, ]
  similarities <- data.frame(
    user_id = character(),
    similarity = numeric(),
    stringsAsFactors = FALSE
  )
  
  for (user_id in rownames(interaction_matrix)) {
    if (user_id == target_user_id) {
      next
    }
    
    user_vector <- interaction_matrix[user_id, ]
    
    # Calculate cosine similarity
    similarity <- calculate_cosine_similarity_vectors(target_user_vector, user_vector)
    
    similarities <- rbind(similarities, data.frame(
      user_id = user_id,
      similarity = similarity,
      stringsAsFactors = FALSE
    ))
  }
  
  return(similarities)
}

calculate_cosine_similarity_vectors <- function(vec1, vec2) {
  if (length(vec1) != length(vec2)) {
    return(0)
  }
  
  # Convert sparse vectors to dense if needed
  if (inherits(vec1, "sparseVector")) {
    vec1 <- as.numeric(vec1)
  }
  if (inherits(vec2, "sparseVector")) {
    vec2 <- as.numeric(vec2)
  }
  
  dot_product <- sum(vec1 * vec2, na.rm = TRUE)
  norm1 <- sqrt(sum(vec1^2, na.rm = TRUE))
  norm2 <- sqrt(sum(vec2^2, na.rm = TRUE))
  
  if (norm1 == 0 || norm2 == 0) {
    return(0)
  }
  
  return(dot_product / (norm1 * norm2))
}

load_recommendation_data <- function() {
  # Load persisted recommendation data if available
  data_file <- "recommendation_data.rds"
  
  if (file.exists(data_file)) {
    tryCatch({
      rec_data <- readRDS(data_file)
      recommendation_state$user_profiles <<- rec_data$user_profiles %||% list()
      recommendation_state$popularity_scores <<- rec_data$popularity_scores %||% list()
      recommendation_state$document_features <<- rec_data$document_features %||% list()
      
      log_event("Loaded recommendation data from disk", "INFO")
    }, error = function(e) {
      log_event(paste("Failed to load recommendation data:", e$message), "WARN")
    })
  }
}

save_recommendation_data <- function() {
  data_file <- "recommendation_data.rds"
  
  tryCatch({
    rec_data <- list(
      user_profiles = recommendation_state$user_profiles,
      popularity_scores = recommendation_state$popularity_scores,
      document_features = recommendation_state$document_features
    )
    
    saveRDS(rec_data, data_file)
    log_event("Saved recommendation data to disk", "INFO")
  }, error = function(e) {
    log_event(paste("Failed to save recommendation data:", e$message), "ERROR")
  })
}

get_recommendation_statistics <- function() {
  return(list(
    total_users = length(recommendation_state$user_profiles),
    total_interactions = sum(sapply(recommendation_state$user_profiles, function(p) length(p$interactions))),
    documents_with_features = length(recommendation_state$document_features),
    popular_documents = length(recommendation_state$popularity_scores),
    cache_size = length(recommendation_state$recommendation_cache),
    algorithms_enabled = sum(sapply(RECOMMENDATION_CONFIG$algorithms, function(x) x$enabled)),
    last_updated = Sys.time()
  ))
}