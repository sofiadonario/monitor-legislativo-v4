# ============================================================================
# MONITOR LEGISLATIVO V4 API - IMPLEMENTATION TEMPLATE
# ============================================================================
# 
# This file provides a complete implementation template for integrating
# the Monitor Legislativo v4 API endpoints with your existing R-Shiny application.
# 
# Author: API Integration Team
# Date: 2024-01-15
# Version: 4.0.0
# License: Academic Research License
# ============================================================================

# Required packages
library(plumber)
library(jsonlite)
library(dplyr)
library(httr)

# ============================================================================
# API CONFIGURATION AND SETUP
# ============================================================================

# API Configuration
API_CONFIG <- list(
  version = "4.0.0",
  base_path = "/api/v4",
  title = "Monitor Legislativo v4 API",
  description = "Brazilian Legislative Research Platform API",
  max_page_size = 1000,
  default_page_size = 50,
  rate_limits = list(
    standard_academic = list(hourly = 1000, minutely = 50),
    research_institution = list(hourly = 5000, minutely = 200),
    bulk_research = list(hourly = 10000, minutely = 500)
  ),
  supported_formats = c("json", "csv"),
  supported_states = c(
    "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
    "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
    "RS", "RO", "RR", "SC", "SP", "SE", "TO"
  ),
  transport_modalities = c("road", "rail", "air", "water", "urban", "cargo", "passenger"),
  document_categories = c("legislation", "regulation", "jurisprudence", "doctrine")
)

# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

#' API Key Authentication Middleware
#' Validates API keys and enforces rate limits
authenticate_api_key <- function(req, res) {
  
  # Extract API key from header
  api_key <- req$HTTP_X_API_KEY
  
  if (is.null(api_key) || api_key == "") {
    res$status <- 401
    return(list(
      status = "error",
      error_code = "MISSING_API_KEY", 
      message = "API key is required. Include your key in the X-API-Key header.",
      documentation_url = "https://api.monitor-legislativo.br/docs#authentication"
    ))
  }
  
  # Validate API key (implement your validation logic)
  key_validation <- validate_api_key(api_key)
  
  if (!key_validation$valid) {
    res$status <- 401
    return(list(
      status = "error",
      error_code = "INVALID_API_KEY",
      message = "The provided API key is invalid or has been revoked.",
      documentation_url = "https://api.monitor-legislativo.br/docs#authentication"
    ))
  }
  
  # Check rate limits
  rate_limit_check <- check_rate_limit(api_key)
  
  if (!rate_limit_check$allowed) {
    res$status <- 429
    res$setHeader("Retry-After", rate_limit_check$retry_after)
    return(list(
      status = "error",
      error_code = "RATE_LIMIT_EXCEEDED",
      message = "API rate limit exceeded. Please wait before making additional requests.",
      details = list(
        limit_type = rate_limit_check$limit_type,
        current_usage = rate_limit_check$current_usage,
        limit = rate_limit_check$limit,
        reset_time = rate_limit_check$reset_time,
        retry_after_seconds = rate_limit_check$retry_after
      )
    ))
  }
  
  # Add user info to request for downstream handlers
  req$user_info <- key_validation$user_info
  
  # Continue to next handler
  plumber::forward()
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

#' Validate API Key
#' @param api_key Character string API key
#' @return List with validation results
validate_api_key <- function(api_key) {
  # Implement your API key validation logic
  # This would typically check against a database
  
  # For template purposes, simple validation
  valid_keys <- list(
    "demo_key_123" = list(
      valid = TRUE,
      user_info = list(
        user_id = "demo_user",
        key_type = "demo",
        permissions = c("read_documents", "basic_analytics")
      )
    ),
    "academic_key_456" = list(
      valid = TRUE,
      user_info = list(
        user_id = "academic_researcher",
        key_type = "research_institution", 
        permissions = c("read_documents", "export_data", "advanced_analytics")
      )
    )
  )
  
  if (api_key %in% names(valid_keys)) {
    return(valid_keys[[api_key]])
  } else {
    return(list(valid = FALSE))
  }
}

#' Check Rate Limits
#' @param api_key Character string API key
#' @return List with rate limit status
check_rate_limit <- function(api_key) {
  # Implement rate limiting logic
  # This would typically use Redis or database to track usage
  
  # For template purposes, always allow
  return(list(
    allowed = TRUE,
    current_usage = 10,
    limit = 1000,
    reset_time = Sys.time() + 3600  # 1 hour from now
  ))
}

#' Format API Response
#' @param data Response data
#' @param status Success/error status
#' @param pagination Pagination info (optional)
#' @param performance Performance metrics (optional)
#' @return Formatted response list
format_api_response <- function(data, status = "success", 
                              pagination = NULL, performance = NULL) {
  
  response <- list(status = status)
  
  if (status == "success") {
    response$data <- data
    
    if (!is.null(pagination)) {
      response$pagination <- pagination
    }
    
    if (!is.null(performance)) {
      response$performance <- performance
    }
    
    response$timestamp <- Sys.time()
  }
  
  return(response)
}

#' Create Pagination Info
#' @param page Current page
#' @param per_page Items per page
#' @param total_results Total number of results
#' @return Pagination metadata
create_pagination <- function(page, per_page, total_results) {
  total_pages <- ceiling(total_results / per_page)
  
  list(
    page = page,
    per_page = per_page,
    total_results = total_results,
    total_pages = total_pages,
    has_next = page < total_pages,
    has_previous = page > 1,
    next_page = if (page < total_pages) page + 1 else NULL,
    previous_page = if (page > 1) page - 1 else NULL
  )
}

# ============================================================================
# CORE ENDPOINT IMPLEMENTATIONS
# ============================================================================

#' Document Search Endpoint
#' @param req Request object
#' @param res Response object
#' @return JSON response with search results
handle_document_search <- function(req, res) {
  
  start_time <- Sys.time()
  
  tryCatch({
    # Extract and validate parameters
    query <- req$args$q %||% ""
    category <- req$args$category %||% "all"
    state <- req$args$state %||% "all"
    municipality <- req$args$municipality
    authority <- req$args$authority
    document_type <- req$args$document_type
    transport_modal <- req$args$transport_modal %||% "all"
    date_start <- req$args$date_start
    date_end <- req$args$date_end
    sort <- req$args$sort %||% "relevance"
    page <- as.numeric(req$args$page %||% 1)
    per_page <- min(as.numeric(req$args$per_page %||% API_CONFIG$default_page_size), 
                   API_CONFIG$max_page_size)
    format_type <- req$args$format %||% "json"
    include_analysis <- as.logical(req$args$include_analysis %||% FALSE)
    
    # Validate parameters
    validation_errors <- validate_search_parameters(
      category, state, transport_modal, sort, page, per_page
    )
    
    if (length(validation_errors) > 0) {
      res$status <- 400
      return(list(
        status = "error",
        error_code = "INVALID_PARAMETER",
        message = "Invalid parameter values provided",
        details = validation_errors
      ))
    }
    
    # Execute search using your existing functions
    # This would integrate with your existing search logic
    search_results <- execute_document_search(
      query = query,
      category = category,
      state = state,
      municipality = municipality,
      authority = authority,
      document_type = document_type,
      transport_modal = transport_modal,
      date_start = date_start,
      date_end = date_end,
      sort = sort,
      limit = per_page,
      offset = (page - 1) * per_page,
      include_analysis = include_analysis
    )
    
    # Calculate performance metrics
    end_time <- Sys.time()
    query_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    # Create pagination info
    pagination <- create_pagination(page, per_page, search_results$total_count)
    
    # Performance metrics
    performance <- list(
      query_time_ms = round(query_time_ms, 2),
      total_documents_searched = search_results$corpus_size,
      index_coverage = 1.0
    )
    
    # Format response
    response_data <- list(
      query = list(
        text = query,
        filters = list(
          category = category,
          state = state,
          transport_modal = transport_modal
        )
      ),
      documents = search_results$documents,
      pagination = pagination,
      performance = performance
    )
    
    return(format_api_response(response_data))
    
  }, error = function(e) {
    res$status <- 500
    return(list(
      status = "error",
      error_code = "INTERNAL_SERVER_ERROR",
      message = "An internal server error occurred",
      details = list(
        timestamp = Sys.time(),
        error = as.character(e$message)
      )
    ))
  })
}

#' Geographic Distribution Endpoint
#' @param req Request object
#' @param res Response object
#' @return JSON response with geographic analysis
handle_geographic_distribution <- function(req, res) {
  
  tryCatch({
    # Extract parameters
    level <- req$args$level %||% "state"
    category <- req$args$category %||% "all"
    transport_modal <- req$args$transport_modal %||% "all"
    date_start <- req$args$date_start
    date_end <- req$args$date_end
    include_geojson <- as.logical(req$args$include_geojson %||% FALSE)
    normalize_population <- as.logical(req$args$normalize_population %||% FALSE)
    
    # Execute geographic analysis using existing functions
    geo_results <- execute_geographic_analysis(
      level = level,
      category = category,
      transport_modal = transport_modal,
      date_start = date_start,
      date_end = date_end,
      include_geojson = include_geojson,
      normalize_population = normalize_population
    )
    
    response_data <- list(
      analysis_parameters = list(
        level = level,
        category = category,
        transport_modal = transport_modal,
        date_range = if (!is.null(date_start) && !is.null(date_end)) {
          list(start = date_start, end = date_end)
        } else NULL
      ),
      geographic_data = geo_results$distribution,
      statistics = geo_results$statistics
    )
    
    return(format_api_response(response_data))
    
  }, error = function(e) {
    res$status <- 500
    return(list(
      status = "error", 
      error_code = "GEOGRAPHIC_ANALYSIS_ERROR",
      message = "Geographic analysis failed",
      details = list(error = as.character(e$message))
    ))
  })
}

#' Citation Generation Endpoint  
#' @param req Request object
#' @param res Response object
#' @return JSON response with generated citations
handle_citation_generation <- function(req, res) {
  
  tryCatch({
    # Parse request body
    body <- jsonlite::fromJSON(req$postBody)
    
    # Extract parameters
    document_ids <- body$document_ids
    citation_format <- body$citation_format %||% "abnt"
    include_access_date <- body$include_access_date %||% TRUE
    access_date <- body$access_date %||% as.character(Sys.Date())
    grouping <- body$grouping %||% "none"
    sort_order <- body$sort_order %||% "alphabetical"
    
    # Validate document IDs
    if (is.null(document_ids) || length(document_ids) == 0) {
      res$status <- 400
      return(list(
        status = "error",
        error_code = "MISSING_DOCUMENT_IDS",
        message = "Document IDs are required for citation generation"
      ))
    }
    
    if (length(document_ids) > 100) {
      res$status <- 400
      return(list(
        status = "error",
        error_code = "TOO_MANY_DOCUMENTS",
        message = "Maximum 100 documents allowed per citation request"
      ))
    }
    
    # Generate citations using existing functions
    citation_results <- generate_document_citations(
      document_ids = document_ids,
      format = citation_format,
      include_access_date = include_access_date,
      access_date = access_date,
      grouping = grouping,
      sort_order = sort_order
    )
    
    response_data <- list(
      citation_format = citation_format,
      total_documents = length(document_ids),
      generated_at = Sys.time(),
      citations = citation_results$individual_citations,
      bibliography = citation_results$formatted_bibliography
    )
    
    return(format_api_response(response_data))
    
  }, error = function(e) {
    res$status <- 500
    return(list(
      status = "error",
      error_code = "CITATION_GENERATION_ERROR", 
      message = "Citation generation failed",
      details = list(error = as.character(e$message))
    ))
  })
}

#' Trend Analysis Endpoint
#' @param req Request object
#' @param res Response object
#' @return JSON response with trend analysis
handle_trend_analysis <- function(req, res) {
  
  tryCatch({
    # Extract parameters
    timeframe <- req$args$timeframe %||% "year"
    date_start <- req$args$date_start %||% "2010-01-01"
    date_end <- req$args$date_end %||% as.character(Sys.Date())
    category <- req$args$category %||% "all"
    transport_modal <- req$args$transport_modal %||% "all"
    authority <- req$args$authority
    geographic_scope <- req$args$geographic_scope %||% "national"
    include_forecasting <- as.logical(req$args$include_forecasting %||% FALSE)
    statistical_tests <- as.logical(req$args$statistical_tests %||% TRUE)
    smoothing_method <- req$args$smoothing_method %||% "moving_average"
    
    # Execute trend analysis using existing functions
    trend_results <- execute_trend_analysis(
      timeframe = timeframe,
      date_start = date_start,
      date_end = date_end,
      category = category,
      transport_modal = transport_modal,
      authority = authority,
      geographic_scope = geographic_scope,
      include_forecasting = include_forecasting,
      statistical_tests = statistical_tests,
      smoothing_method = smoothing_method
    )
    
    response_data <- list(
      analysis_parameters = list(
        timeframe = timeframe,
        date_range = list(start = date_start, end = date_end),
        filters_applied = list(
          category = category,
          transport_modal = transport_modal,
          authority = authority,
          geographic_scope = geographic_scope
        )
      ),
      temporal_data = trend_results$time_series,
      trend_statistics = trend_results$statistics,
      forecasting = if (include_forecasting) trend_results$forecasting else NULL
    )
    
    return(format_api_response(response_data))
    
  }, error = function(e) {
    res$status <- 500
    return(list(
      status = "error",
      error_code = "TREND_ANALYSIS_ERROR",
      message = "Trend analysis failed", 
      details = list(error = as.character(e$message))
    ))
  })
}

#' Bulk Export Endpoint
#' @param req Request object  
#' @param res Response object
#' @return JSON response with export status
handle_bulk_export <- function(req, res) {
  
  tryCatch({
    # Parse request body
    body <- jsonlite::fromJSON(req$postBody)
    
    # Extract parameters
    filters <- body$filters %||% list()
    format_type <- body$format %||% "csv"
    columns <- body$columns %||% "essential"
    filename <- body$filename
    max_documents <- body$max_documents %||% 10000
    include_analysis <- body$include_analysis %||% FALSE
    include_full_text <- body$include_full_text %||% FALSE
    compression <- body$compression %||% "gzip"
    email_notification <- body$email_notification %||% FALSE
    
    # Validate format
    if (!format_type %in% c("csv", "json", "bibtex", "rds", "parquet")) {
      res$status <- 400
      return(list(
        status = "error",
        error_code = "INVALID_FORMAT",
        message = "Unsupported export format. Supported: csv, json, bibtex, rds, parquet"
      ))
    }
    
    # Generate export ID
    export_id <- paste0("export_", digest::digest(list(filters, Sys.time()), algo = "md5"))
    
    # Estimate export size and time
    estimation <- estimate_export_requirements(filters, format_type, max_documents)
    
    if (estimation$document_count > 1000) {
      # Queue for background processing
      queue_export_job(
        export_id = export_id,
        user_id = req$user_info$user_id,
        filters = filters,
        format_type = format_type,
        columns = columns,
        filename = filename,
        max_documents = max_documents,
        include_analysis = include_analysis,
        include_full_text = include_full_text,
        compression = compression,
        email_notification = email_notification
      )
      
      res$status <- 202
      response_data <- list(
        status = "queued",
        export_id = export_id,
        queue_position = get_queue_position(export_id),
        estimated_start_time = Sys.time() + lubridate::minutes(5),
        estimated_completion_time = Sys.time() + lubridate::minutes(estimation$estimated_minutes),
        document_count = estimation$document_count,
        message = "Large export queued for processing. You will receive an email notification when complete."
      )
      
    } else {
      # Process immediately  
      process_immediate_export(
        export_id = export_id,
        user_id = req$user_info$user_id,
        filters = filters,
        format_type = format_type,
        columns = columns,
        filename = filename,
        max_documents = max_documents,
        include_analysis = include_analysis,
        include_full_text = include_full_text,
        compression = compression
      )
      
      response_data <- list(
        status = "initiated",
        export_id = export_id,
        estimated_completion_time = Sys.time() + lubridate::minutes(2),
        estimated_file_size_mb = estimation$file_size_mb,
        document_count = estimation$document_count,
        status_check_url = paste0("/api/v4/export/status/", export_id)
      )
    }
    
    return(format_api_response(response_data))
    
  }, error = function(e) {
    res$status <- 500
    return(list(
      status = "error",
      error_code = "EXPORT_INITIATION_ERROR",
      message = "Export initiation failed",
      details = list(error = as.character(e$message))
    ))
  })
}

# ============================================================================
# PARAMETER VALIDATION FUNCTIONS  
# ============================================================================

#' Validate Search Parameters
#' @param category Document category
#' @param state Brazilian state code
#' @param transport_modal Transport modality
#' @param sort Sort method
#' @param page Page number
#' @param per_page Items per page
#' @return List of validation errors (empty if valid)
validate_search_parameters <- function(category, state, transport_modal, 
                                     sort, page, per_page) {
  
  errors <- list()
  
  # Validate category
  if (!category %in% c("all", API_CONFIG$document_categories)) {
    errors$category <- paste("Invalid category. Valid values:",
                           paste(c("all", API_CONFIG$document_categories), collapse = ", "))
  }
  
  # Validate state
  if (state != "all" && !state %in% API_CONFIG$supported_states) {
    errors$state <- paste("Invalid state code. Valid values:",
                         paste(c("all", API_CONFIG$supported_states), collapse = ", "))
  }
  
  # Validate transport modal
  if (!transport_modal %in% c("all", API_CONFIG$transport_modalities)) {
    errors$transport_modal <- paste("Invalid transport modality. Valid values:",
                                   paste(c("all", API_CONFIG$transport_modalities), collapse = ", "))
  }
  
  # Validate sort
  valid_sorts <- c("relevance", "date_desc", "date_asc", "title_asc", "authority_asc", "importance_desc")
  if (!sort %in% valid_sorts) {
    errors$sort <- paste("Invalid sort method. Valid values:",
                        paste(valid_sorts, collapse = ", "))
  }
  
  # Validate pagination
  if (page < 1 || page > 1000) {
    errors$page <- "Page must be between 1 and 1000"
  }
  
  if (per_page < 1 || per_page > API_CONFIG$max_page_size) {
    errors$per_page <- paste("per_page must be between 1 and", API_CONFIG$max_page_size)
  }
  
  return(errors)
}

# ============================================================================
# INTEGRATION FUNCTIONS WITH EXISTING SYSTEM
# ============================================================================
# These functions would integrate with your existing Monitor Legislativo v4 system

#' Execute Document Search
#' This function would integrate with your existing document search logic
execute_document_search <- function(query, category, state, municipality,
                                  authority, document_type, transport_modal,
                                  date_start, date_end, sort, limit, offset,
                                  include_analysis) {
  
  # INTEGRATION POINT: Replace with your existing get_library_documents() function
  # or similar search implementation
  
  # Example integration:
  documents <- get_library_documents(
    category = if (category == "all") "all" else category,
    search_term = query,
    state = if (state == "all") "all" else state,
    date_start = date_start,
    date_end = date_end,
    sort_by = convert_sort_parameter(sort),
    limit = limit + offset  # Get more to handle offset
  )
  
  # Apply offset
  if (offset > 0 && nrow(documents) > offset) {
    documents <- documents[(offset + 1):nrow(documents), ]
  }
  
  # Limit results  
  if (nrow(documents) > limit) {
    documents <- documents[1:limit, ]
  }
  
  # Convert to API format
  formatted_documents <- convert_documents_to_api_format(documents, include_analysis)
  
  return(list(
    documents = formatted_documents,
    total_count = get_total_documents(query, category, state, transport_modal),
    corpus_size = 134014  # Your total document count
  ))
}

#' Execute Geographic Analysis
#' Integrate with your existing geographic analysis functions
execute_geographic_analysis <- function(level, category, transport_modal,
                                      date_start, date_end, include_geojson,
                                      normalize_population) {
  
  # INTEGRATION POINT: Use your existing geographic analysis functions
  # Example integration with your get_real_state_distribution() function
  
  if (level == "state") {
    distribution <- get_real_state_distribution()
    
    # Convert to API format
    geo_data <- lapply(1:nrow(distribution), function(i) {
      state_row <- distribution[i, ]
      result <- list(
        geographic_id = state_row$estado,
        name = get_state_full_name(state_row$estado),
        document_count = state_row$documents,
        percentage_of_total = round(state_row$documents / sum(distribution$documents) * 100, 1)
      )
      
      if (normalize_population) {
        # Add population normalization
        pop_data <- get_state_population(state_row$estado)
        result$documents_per_capita <- round(state_row$documents / pop_data * 100000, 1)
      }
      
      if (include_geojson) {
        result$geojson <- get_state_geojson(state_row$estado)
      }
      
      return(result)
    })
    
    statistics <- list(
      total_documents = sum(distribution$documents),
      geographic_entities_with_documents = nrow(distribution),
      coverage_percentage = round(nrow(distribution) / 27 * 100, 1)  # 27 Brazilian states
    )
    
    return(list(
      distribution = geo_data,
      statistics = statistics
    ))
  }
}

#' Generate Document Citations
#' Integrate with your existing citation generation logic
generate_document_citations <- function(document_ids, format, include_access_date,
                                      access_date, grouping, sort_order) {
  
  # INTEGRATION POINT: Use your existing citation generation
  # This could integrate with any existing ABNT citation functions you have
  
  citations_list <- list()
  
  for (doc_id in document_ids) {
    # Get document details
    doc <- get_document_by_id(doc_id)  # Your existing function
    
    if (!is.null(doc)) {
      # Generate ABNT citation
      abnt_citation <- generate_abnt_citation(doc, include_access_date, access_date)
      
      # Generate BibTeX
      bibtex_citation <- generate_bibtex_citation(doc)
      
      citation_entry <- list(
        document_id = doc_id,
        formatted_citation = abnt_citation,
        bibtex_entry = bibtex_citation,
        validation = list(
          abnt_compliant = validate_abnt_format(abnt_citation),
          authority_standardized = TRUE,
          date_format_valid = validate_date_format(doc$date)
        )
      )
      
      citations_list[[doc_id]] <- citation_entry
    }
  }
  
  # Format complete bibliography
  bibliography <- format_bibliography(citations_list, grouping, sort_order)
  
  return(list(
    individual_citations = citations_list,
    formatted_bibliography = bibliography
  ))
}

#' Execute Trend Analysis
#' Integrate with your existing trend analysis functions
execute_trend_analysis <- function(timeframe, date_start, date_end, category,
                                 transport_modal, authority, geographic_scope,
                                 include_forecasting, statistical_tests, 
                                 smoothing_method) {
  
  # INTEGRATION POINT: Use your existing trend analysis
  # This could integrate with your get_real_publication_trends() function
  
  trends <- get_real_publication_trends(months_back = 60)  # Your existing function
  
  # Convert to API format with statistical analysis
  formatted_trends <- format_trend_data(trends, timeframe, statistical_tests, smoothing_method)
  
  statistics <- calculate_trend_statistics(formatted_trends, statistical_tests)
  
  result <- list(
    time_series = formatted_trends,
    statistics = statistics
  )
  
  if (include_forecasting) {
    result$forecasting <- generate_trend_forecast(formatted_trends)
  }
  
  return(result)
}

# ============================================================================
# HELPER FUNCTIONS FOR INTEGRATION
# ============================================================================

#' Convert documents to API format
convert_documents_to_api_format <- function(documents, include_analysis = FALSE) {
  
  lapply(1:nrow(documents), function(i) {
    doc <- documents[i, ]
    
    api_doc <- list(
      id = paste0("doc_", i),  # Generate consistent ID
      title = doc$title %||% doc$titulo,
      type = doc$type %||% doc$tipo,
      category = standardize_category(doc$category %||% doc$categoria),
      authority = doc$authority %||% doc$autoridade,
      state = doc$state %||% doc$estado,
      municipality = doc$municipality %||% doc$municipio,
      date = as.character(doc$date %||% doc$data),
      url = doc$url %||% "",
      summary = doc$summary %||% doc$ementa %||% "",
      transport_modal = parse_transport_modalities(doc),
      relevance_score = doc$relevance_score %||% 0.5,
      citation_abnt = generate_quick_citation(doc)
    )
    
    if (include_analysis && exists("add_real_analysis")) {
      # Use your existing NLP analysis function
      analyzed_doc <- add_real_analysis(data.frame(doc))
      
      api_doc$analysis <- list(
        topics = extract_topic_analysis(analyzed_doc),
        entities = extract_entity_analysis(analyzed_doc), 
        complexity_score = calculate_complexity_score(analyzed_doc),
        sentiment_analysis = extract_sentiment_analysis(analyzed_doc)
      )
    }
    
    return(api_doc)
  })
}

#' Convert sort parameter
convert_sort_parameter <- function(api_sort) {
  sort_mapping <- list(
    "relevance" = "relevance",
    "date_desc" = "date_desc",
    "date_asc" = "date_asc", 
    "title_asc" = "title_asc",
    "authority_asc" = "authority_asc",
    "importance_desc" = "relevance"
  )
  
  return(sort_mapping[[api_sort]] %||% "date_desc")
}

#' Standardize document category
standardize_category <- function(category) {
  category_mapping <- list(
    "Legislação" = "legislation",
    "Proposições" = "legislation", 
    "Jurisprudência" = "jurisprudence",
    "Doutrina" = "doctrine",
    "Outros" = "doctrine"
  )
  
  return(category_mapping[[category]] %||% "legislation")
}

# ============================================================================
# API ROUTER SETUP
# ============================================================================

#' Create Monitor Legislativo API Router
#' @return Plumber API object
create_monitor_legislativo_api <- function() {
  
  pr <- plumber::pr()
  
  # Add authentication middleware
  pr <- pr %>% 
    pr_hook("preexec", authenticate_api_key)
  
  # Authentication endpoints
  pr <- pr %>%
    pr_get("/auth/validate", function(req, res) {
      list(
        valid = TRUE,
        key_type = req$user_info$key_type,
        permissions = req$user_info$permissions,
        rate_limits = get_user_rate_limits(req$user_info$key_type)
      )
    }) %>%
    pr_get("/auth/usage", function(req, res) {
      get_user_usage_statistics(req$user_info$user_id)
    })
  
  # Core document endpoints  
  pr <- pr %>%
    pr_get("/documents", handle_document_search) %>%
    pr_get("/documents/<id>", function(req, res, id) {
      handle_document_detail(req, res, id)
    })
  
  # Geographic analysis endpoints
  pr <- pr %>%
    pr_get("/geographic/distribution", handle_geographic_distribution) %>%
    pr_get("/geographic/corridors", function(req, res) {
      handle_corridor_analysis(req, res)
    })
  
  # Citation endpoints
  pr <- pr %>%
    pr_post("/citations/generate", handle_citation_generation) %>%
    pr_get("/citations/network", function(req, res) {
      handle_citation_network_analysis(req, res)
    })
  
  # Analytics endpoints
  pr <- pr %>%
    pr_get("/analytics/trends", handle_trend_analysis) %>%
    pr_get("/analytics/complexity", function(req, res) {
      handle_complexity_analysis(req, res)
    })
  
  # Export endpoints
  pr <- pr %>%
    pr_post("/export/documents", handle_bulk_export) %>%
    pr_get("/export/status/<export_id>", function(req, res, export_id) {
      handle_export_status(req, res, export_id)
    }) %>%
    pr_get("/export/download/<export_id>", function(req, res, export_id) {
      handle_export_download(req, res, export_id)
    })
  
  # Research tools
  pr <- pr %>%
    pr_get("/research/keywords", function(req, res) {
      handle_keyword_analysis(req, res)
    }) %>%
    pr_post("/research/comparison", function(req, res) {
      handle_comparative_analysis(req, res)
    })
  
  # Metadata endpoints
  pr <- pr %>%
    pr_get("/meta/schema", function(req, res) {
      handle_schema_info(req, res)
    }) %>%
    pr_get("/meta/statistics", function(req, res) {
      handle_corpus_statistics(req, res)
    }) %>%
    pr_get("/meta/authorities", function(req, res) {
      handle_authority_directory(req, res)
    })
  
  # Add OpenAPI documentation
  pr <- pr %>%
    pr_set_api_spec(yaml::read_yaml("api/openapi-spec.yaml"))
  
  return(pr)
}

# ============================================================================
# DEPLOYMENT CONFIGURATION
# ============================================================================

#' Start Monitor Legislativo API Server
#' @param host Host address (default: "0.0.0.0" for production)
#' @param port Port number (default: 8000)
#' @return Running API server
start_api_server <- function(host = "0.0.0.0", port = 8000) {
  
  cat("🚀 Starting Monitor Legislativo v4 API Server...\n")
  cat("📊 Base URL: http://", host, ":", port, "/api/v4\n")
  cat("📚 Documentation: http://", host, ":", port, "/__docs__/\n")
  cat("🔧 OpenAPI Spec: http://", host, ":", port, "/openapi.json\n")
  
  api <- create_monitor_legislativo_api()
  
  # Add CORS support for web clients
  api <- api %>%
    pr_filter("cors", function(req, res) {
      res$setHeader("Access-Control-Allow-Origin", "*")
      res$setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
      res$setHeader("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
      
      if (req$REQUEST_METHOD == "OPTIONS") {
        res$status <- 200
        return(list())
      } else {
        plumber::forward()
      }
    })
  
  # Add request logging
  api <- api %>%
    pr_filter("logger", function(req) {
      cat(paste(
        format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
        req$REQUEST_METHOD,
        req$PATH_INFO,
        "\n"
      ))
      plumber::forward()
    })
  
  # Start server
  api$run(host = host, port = port)
}

# ============================================================================
# USAGE EXAMPLES
# ============================================================================

# To integrate this API with your existing Monitor Legislativo v4 application:
#
# 1. Source this file in your main app.R:
#    source("api/api-implementation-template.R")
#
# 2. Start the API server alongside your Shiny app:
#    if (Sys.getenv("ENABLE_API") == "TRUE") {
#      future::future({
#        start_api_server(host = "0.0.0.0", port = 8000)
#      })
#    }
#
# 3. Update your existing functions to support the API endpoints:
#    - Ensure get_library_documents() supports all the filtering parameters
#    - Make sure geographic analysis functions return properly formatted data
#    - Implement citation generation functions if not already available
#
# 4. Configure environment variables:
#    - API_ENABLE=TRUE
#    - API_HOST=0.0.0.0  
#    - API_PORT=8000
#
# 5. Deploy with your Railway configuration:
#    The API will be accessible at: https://your-railway-app.up.railway.app/api/v4

cat("✅ Monitor Legislativo v4 API Implementation Template Loaded\n")
cat("📝 Review integration points marked with 'INTEGRATION POINT' comments\n")
cat("🔧 Customize authentication and rate limiting as needed\n")
cat("🚀 Call start_api_server() to launch the API\n")