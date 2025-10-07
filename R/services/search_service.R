# search_service.R - Modular Search Data Service
# ============================================================================
# Purpose: Provides paginated, testable search functionality for documents
# Created: 2025
# ============================================================================

library(dplyr)
library(stringr)
library(DBI)

#' SearchService class for document retrieval
#'
#' @field db_connection Database connection object
#' @field cache_enabled Whether to use caching
#' @field default_limit Default page size
SearchService <- R6::R6Class("SearchService",
  public = list(
    db_connection = NULL,
    cache_enabled = FALSE,
    default_limit = 50,
    max_limit = 1000,

    #' Initialize SearchService
    #'
    #' @param db_connection DBI database connection
    #' @param cache_enabled Enable caching (default FALSE)
    #' @param default_limit Default page size (default 50)
    initialize = function(db_connection = NULL, cache_enabled = FALSE, default_limit = 50) {
      self$db_connection <- db_connection
      self$cache_enabled <- cache_enabled
      self$default_limit <- default_limit
      private$init_cache()
    },

    #' Search for documents with pagination
    #'
    #' @param category Document category filter
    #' @param search_term Search query
    #' @param state State filter
    #' @param date_start Start date filter
    #' @param date_end End date filter
    #' @param sort_by Sort order
    #' @param limit Page size (max 1000)
    #' @param offset Page offset
    #' @param use_semantic_search Enable semantic search
    #' @return Data frame of documents
    search_documents = function(category = "all",
                              search_term = "",
                              state = "all",
                              date_start = NULL,
                              date_end = NULL,
                              sort_by = "date_desc",
                              limit = NULL,
                              offset = 0,
                              use_semantic_search = FALSE) {

      # Validate and sanitize inputs
      limit <- private$validate_limit(limit)
      offset <- max(0, as.integer(offset))
      search_term <- private$sanitize_search_term(search_term)

      # Build cache key
      cache_key <- private$build_cache_key(
        category, search_term, state, date_start, date_end,
        sort_by, limit, offset, use_semantic_search
      )

      # Check cache
      if (self$cache_enabled) {
        cached <- private$get_from_cache(cache_key)
        if (!is.null(cached)) {
          return(cached)
        }
      }

      # Fetch data
      results <- NULL

      if (!is.null(self$db_connection)) {
        results <- private$fetch_from_database(
          category, search_term, state, date_start, date_end,
          sort_by, limit, offset, use_semantic_search
        )
      } else {
        results <- private$fetch_from_csv(
          category, search_term, state, date_start, date_end,
          sort_by, limit, offset, use_semantic_search
        )
      }

      # Handle empty results
      if (is.null(results) || nrow(results) == 0) {
        results <- data.frame()
      }

      # Cache results
      if (self$cache_enabled && nrow(results) > 0) {
        private$save_to_cache(cache_key, results)
      }

      return(results)
    },

    #' Get total count of matching documents
    #'
    #' @param ... Same parameters as search_documents
    #' @return Integer count
    count_documents = function(category = "all",
                              search_term = "",
                              state = "all",
                              date_start = NULL,
                              date_end = NULL) {

      if (!is.null(self$db_connection)) {
        return(private$count_from_database(category, search_term, state, date_start, date_end))
      } else {
        return(private$count_from_csv(category, search_term, state, date_start, date_end))
      }
    },

    #' Clear search cache
    clear_cache = function() {
      private$cache <- list()
    }
  ),

  private = list(
    cache = list(),
    csv_data = NULL,

    #' Initialize cache
    init_cache = function() {
      private$cache <- list()
    },

    #' Validate limit parameter
    validate_limit = function(limit) {
      if (is.null(limit)) {
        return(self$default_limit)
      }
      limit <- as.integer(limit)
      return(min(max(1, limit), self$max_limit))
    },

    #' Sanitize search term to prevent injection
    sanitize_search_term = function(search_term) {
      if (is.null(search_term) || search_term == "") {
        return("")
      }
      # Remove potentially dangerous characters
      search_term <- gsub("[<>\";]", "", search_term)
      search_term <- gsub("(?<![[:alnum:]])'(?![[:alnum:]])", "", search_term, perl = TRUE)
      return(search_term)
    },

    #' Build cache key from parameters
    build_cache_key = function(...) {
      paste(list(...), collapse = "_")
    },

    #' Get from cache
    get_from_cache = function(key) {
      if (key %in% names(private$cache)) {
        item <- private$cache[[key]]
        if (Sys.time() - item$timestamp < 300) { # 5 minute TTL
          return(item$data)
        }
      }
      return(NULL)
    },

    #' Save to cache
    save_to_cache = function(key, data) {
      private$cache[[key]] <- list(
        data = data,
        timestamp = Sys.time()
      )
    },

    #' Fetch documents from database
    fetch_from_database = function(category, search_term, state,
                                  date_start, date_end, sort_by,
                                  limit, offset, use_semantic_search) {

      query <- "SELECT * FROM documents WHERE 1=1"
      params <- list()

      # Add filters
      if (category != "all" && category != "") {
        query <- paste0(query, " AND categoria = ?")
        params <- append(params, category)
      }

      if (state != "all" && state != "") {
        query <- paste0(query, " AND estado = ?")
        params <- append(params, state)
      }

      if (!is.null(date_start)) {
        query <- paste0(query, " AND data >= ?")
        params <- append(params, as.character(date_start))
      }

      if (!is.null(date_end)) {
        query <- paste0(query, " AND data <= ?")
        params <- append(params, as.character(date_end))
      }

      # Add search term filter
      if (search_term != "") {
        if (use_semantic_search) {
          # Use full text search if available
          query <- paste0(query, " AND (titulo ILIKE ? OR resumo ILIKE ?)")
          search_pattern <- paste0("%", search_term, "%")
          params <- append(params, list(search_pattern, search_pattern))
        } else {
          # Basic text search
          query <- paste0(query, " AND (titulo ILIKE ? OR resumo ILIKE ?)")
          search_pattern <- paste0("%", search_term, "%")
          params <- append(params, list(search_pattern, search_pattern))
        }
      }

      # Add sorting
      sort_col <- switch(sort_by,
        "date_desc" = "data DESC",
        "date_asc" = "data ASC",
        "relevance" = "titulo ASC",
        "data DESC"
      )
      query <- paste0(query, " ORDER BY ", sort_col)

      # Add pagination
      query <- paste0(query, " LIMIT ", limit, " OFFSET ", offset)

      # Execute query
      tryCatch({
        if (length(params) > 0) {
          result <- DBI::dbGetQuery(self$db_connection, query, params = params)
        } else {
          result <- DBI::dbGetQuery(self$db_connection, query)
        }
        return(result)
      }, error = function(e) {
        warning(paste("Database query failed:", e$message))
        return(data.frame())
      })
    },

    #' Fetch documents from CSV fallback
    fetch_from_csv = function(category, search_term, state,
                            date_start, date_end, sort_by,
                            limit, offset, use_semantic_search) {

      # Load CSV data if not already loaded
      if (is.null(private$csv_data)) {
        csv_files <- c(
          "data_current/processed/production/lexml_unified_dataset.csv",
          "railway_data_50k.csv",
          "railway_data_10k.csv"
        )

        for (csv_file in csv_files) {
          if (file.exists(csv_file)) {
            tryCatch({
              private$csv_data <- read.csv(csv_file, stringsAsFactors = FALSE)
              break
            }, error = function(e) {
              warning(paste("Failed to load CSV:", e$message))
            })
          }
        }
      }

      if (is.null(private$csv_data)) {
        return(data.frame())
      }

      # Apply filters
      filtered <- private$csv_data

      if (category != "all" && category != "") {
        filtered <- filtered[filtered$categoria == category, ]
      }

      if (state != "all" && state != "") {
        filtered <- filtered[filtered$estado == state, ]
      }

      if (!is.null(date_start)) {
        filtered <- filtered[as.Date(filtered$data) >= as.Date(date_start), ]
      }

      if (!is.null(date_end)) {
        filtered <- filtered[as.Date(filtered$data) <= as.Date(date_end), ]
      }

      # Apply search
      if (search_term != "") {
        title_match <- grepl(search_term, filtered$titulo, ignore.case = TRUE)
        summary_match <- grepl(search_term, filtered$resumo, ignore.case = TRUE)
        filtered <- filtered[title_match | summary_match, ]
      }

      # Sort
      if (sort_by == "date_desc") {
        filtered <- filtered[order(filtered$data, decreasing = TRUE), ]
      } else if (sort_by == "date_asc") {
        filtered <- filtered[order(filtered$data), ]
      }

      # Paginate
      start_idx <- offset + 1
      end_idx <- min(offset + limit, nrow(filtered))

      if (start_idx <= nrow(filtered)) {
        return(filtered[start_idx:end_idx, ])
      } else {
        return(data.frame())
      }
    },

    #' Count documents in database
    count_from_database = function(category, search_term, state, date_start, date_end) {
      query <- "SELECT COUNT(*) as count FROM documents WHERE 1=1"
      params <- list()

      # Add filters (same as fetch_from_database)
      if (category != "all" && category != "") {
        query <- paste0(query, " AND categoria = ?")
        params <- append(params, category)
      }

      if (state != "all" && state != "") {
        query <- paste0(query, " AND estado = ?")
        params <- append(params, state)
      }

      if (!is.null(date_start)) {
        query <- paste0(query, " AND data >= ?")
        params <- append(params, as.character(date_start))
      }

      if (!is.null(date_end)) {
        query <- paste0(query, " AND data <= ?")
        params <- append(params, as.character(date_end))
      }

      if (search_term != "") {
        query <- paste0(query, " AND (titulo ILIKE ? OR resumo ILIKE ?)")
        search_pattern <- paste0("%", search_term, "%")
        params <- append(params, list(search_pattern, search_pattern))
      }

      tryCatch({
        if (length(params) > 0) {
          result <- DBI::dbGetQuery(self$db_connection, query, params = params)
        } else {
          result <- DBI::dbGetQuery(self$db_connection, query)
        }
        return(result$count[1])
      }, error = function(e) {
        warning(paste("Count query failed:", e$message))
        return(0)
      })
    },

    #' Count documents in CSV
    count_from_csv = function(category, search_term, state, date_start, date_end) {
      # Use same filtering logic as fetch_from_csv but return count
      filtered <- private$fetch_from_csv(
        category, search_term, state, date_start, date_end,
        "date_desc", .Machine$integer.max, 0, FALSE
      )
      return(nrow(filtered))
    }
  )
)
