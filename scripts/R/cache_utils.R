# ============================================================================
# ⚠️  DEPRECATED: This file is a duplicate and should NOT be used!
# ============================================================================
#
# This is a duplicate of R/utils/cache_utils.R which is the canonical version.
#
# PLEASE USE: source("R/utils/cache_utils.R") instead
#
# This file is retained for historical reference but will be removed in a
# future version. See docs/CACHE_CONSOLIDATION.md for details.
#
# Migration: Priority 5 - Cache File Consolidation (November 2025)
# ============================================================================

# Cache Utilities Module for Monitor Legislativo v4
# Implements caching for improved performance

library(digest)

# Global cache storage
app_cache <- new.env()

#' Initialize cache system
#' @param cache_dir Directory for file-based cache (optional)
init_cache <- function(cache_dir = "data_current/cache") {
  if (!dir.exists(cache_dir)) {
    dir.create(cache_dir, recursive = TRUE)
  }
  
  # Clean up old cache files (older than 1 hour)
  cleanup_cache_files(cache_dir, max_age_hours = 1)
  
  cat("Cache system initialized\n")
}

#' Generate cache key from parameters
#' @param ... Parameters to include in cache key
#' @return Character string cache key
generate_cache_key <- function(...) {
  params <- list(...)
  key_string <- paste(params, collapse = "_")
  return(digest(key_string, algo = "md5"))
}

#' Get cached result
#' @param cache_key Cache key
#' @param use_file_cache Whether to use file-based caching
#' @return Cached result or NULL if not found
get_cached_result <- function(cache_key, use_file_cache = FALSE) {
  # Try memory cache first
  if (exists(cache_key, envir = app_cache)) {
    cache_entry <- get(cache_key, envir = app_cache)
    
    # Check if cache is still valid (5 minutes for memory cache)
    if (Sys.time() - cache_entry$timestamp < 300) {
      cat("Cache hit (memory):", cache_key, "\n")
      return(cache_entry$data)
    } else {
      # Remove expired cache
      rm(list = cache_key, envir = app_cache)
    }
  }
  
  # Try file cache if enabled
  if (use_file_cache) {
    cache_file <- file.path("data_current/cache", paste0(cache_key, ".rds"))
    if (file.exists(cache_file)) {
      file_info <- file.info(cache_file)
      
      # Check if file cache is still valid (15 minutes for file cache)
      if (Sys.time() - file_info$mtime < 900) {
        tryCatch({
          cached_data <- readRDS(cache_file)
          cat("Cache hit (file):", cache_key, "\n")
          
          # Also store in memory cache
          app_cache[[cache_key]] <- list(
            data = cached_data,
            timestamp = Sys.time()
          )
          
          return(cached_data)
        }, error = function(e) {
          cat("Error reading cache file:", e$message, "\n")
          unlink(cache_file)
        })
      } else {
        # Remove expired file cache
        unlink(cache_file)
      }
    }
  }
  
  return(NULL)
}

#' Store result in cache
#' @param cache_key Cache key
#' @param data Data to cache
#' @param use_file_cache Whether to use file-based caching
store_cached_result <- function(cache_key, data, use_file_cache = FALSE) {
  # Store in memory cache
  app_cache[[cache_key]] <- list(
    data = data,
    timestamp = Sys.time()
  )
  
  # Store in file cache if enabled
  if (use_file_cache) {
    cache_file <- file.path("data_current/cache", paste0(cache_key, ".rds"))
    tryCatch({
      saveRDS(data, cache_file)
      cat("Data cached (file):", cache_key, "\n")
    }, error = function(e) {
      cat("Error saving cache file:", e$message, "\n")
    })
  } else {
    cat("Data cached (memory):", cache_key, "\n")
  }
}

#' Clear all cache
clear_cache <- function() {
  # Clear memory cache
  rm(list = ls(envir = app_cache), envir = app_cache)
  
  # Clear file cache
  cache_dir <- "data_current/cache"
  if (dir.exists(cache_dir)) {
    files <- list.files(cache_dir, pattern = "\\.rds$", full.names = TRUE)
    unlink(files)
  }
  
  cat("Cache cleared\n")
}

#' Clean up old cache files
#' @param cache_dir Cache directory
#' @param max_age_hours Maximum age in hours
cleanup_cache_files <- function(cache_dir, max_age_hours = 1) {
  if (!dir.exists(cache_dir)) {
    return()
  }
  
  tryCatch({
    files <- list.files(cache_dir, pattern = "\\.rds$", full.names = TRUE)
    cutoff_time <- Sys.time() - (max_age_hours * 3600)
    
    for (file in files) {
      if (file.info(file)$mtime < cutoff_time) {
        unlink(file)
        cat("Removed old cache file:", basename(file), "\n")
      }
    }
    
  }, error = function(e) {
    cat("Error cleaning cache files:", e$message, "\n")
  })
}

#' Cached version of get_documents
#' @param limit Number of documents to retrieve
#' @param use_cache Whether to use caching
#' @return Documents data frame
cached_get_documents <- function(limit = 100, use_cache = TRUE) {
  if (!use_cache) {
    return(get_documents(limit))
  }
  
  cache_key <- generate_cache_key("documents", limit)
  cached_result <- get_cached_result(cache_key, use_file_cache = TRUE)
  
  if (!is.null(cached_result)) {
    return(cached_result)
  }
  
  # Fetch fresh data
  result <- get_documents(limit)
  
  if (!is.null(result)) {
    store_cached_result(cache_key, result, use_file_cache = TRUE)
  }
  
  return(result)
}

#' Cached version of get_document_stats
#' @param use_cache Whether to use caching
#' @return Document statistics
cached_get_document_stats <- function(use_cache = TRUE) {
  if (!use_cache) {
    return(get_document_stats())
  }
  
  cache_key <- generate_cache_key("document_stats")
  cached_result <- get_cached_result(cache_key, use_file_cache = TRUE)
  
  if (!is.null(cached_result)) {
    return(cached_result)
  }
  
  # Fetch fresh data
  result <- get_document_stats()
  
  if (!is.null(result)) {
    store_cached_result(cache_key, result, use_file_cache = TRUE)
  }
  
  return(result)
}

#' Cached version of get_search_analytics
#' @param use_cache Whether to use caching
#' @return Search analytics data
cached_get_search_analytics <- function(use_cache = TRUE) {
  if (!use_cache) {
    return(get_search_analytics())
  }
  
  cache_key <- generate_cache_key("search_analytics")
  cached_result <- get_cached_result(cache_key, use_file_cache = TRUE)
  
  if (!is.null(cached_result)) {
    return(cached_result)
  }
  
  # Fetch fresh data
  result <- get_search_analytics()
  
  if (!is.null(result)) {
    store_cached_result(cache_key, result, use_file_cache = TRUE)
  }
  
  return(result)
}

#' Cached version of get_state_document_counts
#' @param use_cache Whether to use caching
#' @return State document counts
cached_get_state_document_counts <- function(use_cache = TRUE) {
  if (!use_cache) {
    return(get_state_document_counts())
  }
  
  cache_key <- generate_cache_key("state_document_counts")
  cached_result <- get_cached_result(cache_key, use_file_cache = TRUE)
  
  if (!is.null(cached_result)) {
    return(cached_result)
  }
  
  # Fetch fresh data
  result <- get_state_document_counts()
  
  if (!is.null(result)) {
    store_cached_result(cache_key, result, use_file_cache = TRUE)
  }
  
  return(result)
}

#' Cached version of get_document_types
#' @param use_cache Whether to use caching
#' @return Document types
cached_get_document_types <- function(use_cache = TRUE) {
  if (!use_cache) {
    return(get_document_types())
  }
  
  cache_key <- generate_cache_key("document_types")
  cached_result <- get_cached_result(cache_key, use_file_cache = FALSE)
  
  if (!is.null(cached_result)) {
    return(cached_result)
  }
  
  # Fetch fresh data
  result <- get_document_types()
  
  if (!is.null(result)) {
    store_cached_result(cache_key, result, use_file_cache = FALSE)
  }
  
  return(result)
}

#' Cached version of get_states
#' @param use_cache Whether to use caching
#' @return States list
cached_get_states <- function(use_cache = TRUE) {
  if (!use_cache) {
    return(get_states())
  }
  
  cache_key <- generate_cache_key("states")
  cached_result <- get_cached_result(cache_key, use_file_cache = FALSE)
  
  if (!is.null(cached_result)) {
    return(cached_result)
  }
  
  # Fetch fresh data
  result <- get_states()
  
  if (!is.null(result)) {
    store_cached_result(cache_key, result, use_file_cache = FALSE)
  }
  
  return(result)
}

#' Get cache statistics
#' @return List with cache statistics
get_cache_stats <- function() {
  memory_cache_size <- length(ls(envir = app_cache))
  
  cache_dir <- "data/cache"
  file_cache_size <- 0
  file_cache_total_size <- 0
  
  if (dir.exists(cache_dir)) {
    files <- list.files(cache_dir, pattern = "\\.rds$", full.names = TRUE)
    file_cache_size <- length(files)
    file_cache_total_size <- sum(file.info(files)$size, na.rm = TRUE)
  }
  
  return(list(
    memory_cache_entries = memory_cache_size,
    file_cache_entries = file_cache_size,
    file_cache_size_mb = round(file_cache_total_size / 1024 / 1024, 2),
    cache_directory = cache_dir
  ))
}