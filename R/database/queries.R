# Database Queries Module
# Monitor Legislativo v4 - Optimized SQL Queries
# ==============================================

#' Get Documents with Fallback Support
#' 
#' Retrieves legislative documents from database or CSV fallback
#' Supports filtering, pagination, and academic research standards
#' 
#' @param pool Database connection pool (NULL for CSV fallback)
#' @param limit Maximum number of documents to retrieve
#' @param offset Starting offset for pagination
#' @param filters List of filters (estado, tipo, ano_min, ano_max, etc.)
#' @return Data frame of legislative documents
#' @export
get_documents <- function(pool = NULL, limit = 1000, offset = 0, filters = list()) {
  
  # Database query
  if (!is.null(pool)) {
    tryCatch({
      
      # Base query
      sql_query <- "SELECT id, urn, titulo, content, tipo, ano, data_publicacao, 
                           orgao_emissor, estado, municipio, fonte, created_at
                    FROM documents"
      
      where_conditions <- c()
      params <- list()
      
      # Add filters dynamically
      if (!isTRUE(is.null(filters$estado)) && filters$estado != "") {
        where_conditions <- c(where_conditions, paste("estado = $", length(params) + 1))
        params <- append(params, filters$estado)
      }
      
      if (!isTRUE(is.null(filters$tipo)) && filters$tipo != "") {
        where_conditions <- c(where_conditions, paste("tipo = $", length(params) + 1))
        params <- append(params, filters$tipo)
      }
      
      if (!is.null(filters$ano_min)) {
        where_conditions <- c(where_conditions, paste("ano >= $", length(params) + 1))
        params <- append(params, filters$ano_min)
      }
      
      if (!is.null(filters$ano_max)) {
        where_conditions <- c(where_conditions, paste("ano <= $", length(params) + 1))
        params <- append(params, filters$ano_max)
      }
      
      # Add WHERE clause if filters exist
      if (length(where_conditions) > 0) {
        sql_query <- paste(sql_query, "WHERE", paste(where_conditions, collapse = " AND "))
      }
      
      # Add ordering and pagination
      sql_query <- paste(sql_query, "ORDER BY data_publicacao DESC, id DESC")
      sql_query <- paste(sql_query, "LIMIT $", length(params) + 1)
      params <- append(params, limit)
      
      if (offset > 0) {
        sql_query <- paste(sql_query, "OFFSET $", length(params) + 1)
        params <- append(params, offset)
      }
      
      # Execute query with security controls
      result <- execute_secure_query(pool, sql_query, params)
      return(result)
      
    }, error = function(e) {
      warning("Database query failed, falling back to CSV: ", e$message)
    })
  }
  
  # CSV fallback
  return(get_documents_from_csv(limit, offset, filters))
}

#' Get Documents from CSV Files
#' 
#' Fallback function to retrieve documents from CSV files
#' 
#' @param limit Maximum number of documents
#' @param offset Starting offset
#' @param filters List of filters
#' @return Data frame of documents
get_documents_from_csv <- function(limit = 1000, offset = 0, filters = list()) {
  
  csv_files <- c(
    "data/monitor_legislativo_cleaned.csv",
    "data_current/monitor_legislativo_cleaned.csv", 
    "data/sample_data.csv"
  )
  
  for (csv_file in csv_files) {
    if (file.exists(csv_file)) {
      tryCatch({
        # Read CSV file
        data <- read.csv(csv_file, stringsAsFactors = FALSE, nrows = limit * 2)  # Read extra for filtering
        
        # Apply filters
        if (!isTRUE(is.null(filters$estado)) && filters$estado != "" && "estado" %in% names(data)) {
          data <- data[data$estado == filters$estado, ]
        }
        
        if (!isTRUE(is.null(filters$tipo)) && filters$tipo != "" && "tipo" %in% names(data)) {
          data <- data[data$tipo == filters$tipo, ]
        }
        
        if (!isTRUE(is.null(filters$ano_min)) && "ano" %in% names(data)) {
          data <- data[data$ano >= filters$ano_min, ]
        }
        
        if (!isTRUE(is.null(filters$ano_max)) && "ano" %in% names(data)) {
          data <- data[data$ano <= filters$ano_max, ]
        }
        
        # Apply offset and limit
        if (nrow(data) > offset) {
          start_idx <- offset + 1
          end_idx <- min(nrow(data), offset + limit)
          data <- data[start_idx:end_idx, ]
        } else {
          data <- data[0, ]  # Empty data frame
        }
        
        return(data)
        
      }, error = function(e) {
        warning("Failed to read CSV file: ", csv_file, " - ", e$message)
      })
    }
  }
  
  # If all CSV files failed, return empty data frame
  return(data.frame(
    id = integer(0),
    titulo = character(0),
    content = character(0),
    tipo = character(0),
    ano = integer(0),
    estado = character(0),
    municipio = character(0)
  ))
}

#' Search Documents with Full-Text Search
#' 
#' Performs intelligent search across legislative documents
#' Supports PostgreSQL full-text search and CSV text matching
#' 
#' @param pool Database connection pool
#' @param query Search query string
#' @param filters Additional filters
#' @param limit Maximum results
#' @return Data frame of matching documents with relevance scores
#' @export
search_documents <- function(pool = NULL, query = "", filters = list(), limit = 100) {
  
  if (query == "" || isTRUE(is.null(query))) {
    return(get_documents(pool, limit = limit, filters = filters))
  }
  
  # Database search with full-text search
  if (!is.null(pool)) {
    tryCatch({
      
      # PostgreSQL full-text search query
      sql_base <- "
        SELECT d.id, d.urn, d.titulo, d.content, d.tipo, d.ano, d.estado, d.municipio,
               ts_rank(to_tsvector('portuguese', COALESCE(d.content, '') || ' ' || COALESCE(d.titulo, '')), 
                       plainto_tsquery('portuguese', $1)) as relevance
        FROM documents d
        WHERE (to_tsvector('portuguese', COALESCE(d.content, '') || ' ' || COALESCE(d.titulo, '')) 
               @@ plainto_tsquery('portuguese', $1))
      "
      
      params <- list(query)
      
      # Add filters dynamically
      if (!is.null(filters$ano_min)) {
        sql_base <- paste(sql_base, "AND d.ano >= $", length(params) + 1)
        params <- append(params, filters$ano_min)
      }
      
      if (!isTRUE(is.null(filters$estado)) && filters$estado != "") {
        sql_base <- paste(sql_base, "AND d.estado = $", length(params) + 1)
        params <- append(params, filters$estado)
      }
      
      if (!isTRUE(is.null(filters$tipo)) && filters$tipo != "") {
        sql_base <- paste(sql_base, "AND d.tipo = $", length(params) + 1)
        params <- append(params, filters$tipo)
      }
      
      # Add ordering and limit
      sql_base <- paste(sql_base, "ORDER BY relevance DESC, d.data_publicacao DESC LIMIT $", length(params) + 1)
      params <- append(params, limit)
      
      # Execute search query with security controls
      result <- execute_secure_query(pool, sql_base, params)
      return(result)
      
    }, error = function(e) {
      warning("Database search failed, falling back to CSV search: ", e$message)
    })
  }
  
  # CSV fallback search
  return(search_documents_csv(query, filters, limit))
}

#' Search Documents in CSV Files
#' 
#' Fallback text search for CSV files
#' 
#' @param query Search query
#' @param filters Additional filters
#' @param limit Maximum results
#' @return Data frame of matching documents
search_documents_csv <- function(query = "", filters = list(), limit = 100) {
  
  # Get documents from CSV
  all_docs <- get_documents_from_csv(limit = 5000, filters = filters)  # Get larger set for searching
  
  if (isTRUE(nrow(all_docs) == 0) || query == "") {
    return(all_docs[1:min(limit, nrow(all_docs)), ])
  }
  
  # Simple text search
  query_lower <- tolower(query)
  
  # Search in title and content
  title_matches <- if("titulo" %in% names(all_docs)) {
    grepl(query_lower, tolower(all_docs$titulo), fixed = TRUE)
  } else {
    rep(FALSE, nrow(all_docs))
  }
  
  content_matches <- if("content" %in% names(all_docs)) {
    grepl(query_lower, tolower(all_docs$content), fixed = TRUE)
  } else {
    rep(FALSE, nrow(all_docs))
  }
  
  # Combine matches
  matching_docs <- all_docs[title_matches | content_matches, ]
  
  # Simple relevance scoring (title matches get higher score)
  if (isTRUE(nrow(matching_docs) > 0) && "titulo" %in% names(matching_docs)) {
    matching_docs$relevance <- ifelse(
      grepl(query_lower, tolower(matching_docs$titulo), fixed = TRUE), 
      2, 1
    )
    
    # Sort by relevance
    matching_docs <- matching_docs[order(matching_docs$relevance, decreasing = TRUE), ]
  }
  
  # Return limited results
  return(matching_docs[1:min(limit, nrow(matching_docs)), ])
}

#' Get Total Document Count
#' 
#' Returns total number of documents in the system
#' 
#' @param pool Database connection pool
#' @return Numeric count of total documents
#' @export
get_total_documents <- function(pool = NULL) {
  
  if (!is.null(pool)) {
    tryCatch({
      result <- execute_secure_query(pool, "SELECT COUNT(*) as total FROM documents")
      return(as.numeric(result$total))
    }, error = function(e) {
      warning("Database count query failed: ", e$message)
    })
  }
  
  # CSV fallback
  return(get_csv_document_count())
}

#' Get Unique Values for Filters
#' 
#' Returns unique values for filter dropdown menus
#' 
#' @param pool Database connection pool
#' @param column Column name to get unique values for
#' @return Character vector of unique values
#' @export
get_filter_values <- function(pool = NULL, column = "estado") {
  
  if (!is.null(pool)) {
    tryCatch({
      # Validate column name to prevent SQL injection
      allowed_columns <- c("estado", "tipo", "ano", "orgao_emissor", "municipio")
      if (!(column %in% allowed_columns)) {
        log_security_event("SQL_INJECTION_ATTEMPT", paste("Invalid column name:", column))
        stop("Invalid column name")
      }
      
      sql_query <- paste("SELECT DISTINCT", column, "FROM documents WHERE", column, "IS NOT NULL AND", column, "!= '' ORDER BY", column)
      result <- execute_secure_query(pool, sql_query)
      return(result[[column]])
    }, error = function(e) {
      warning("Filter query failed: ", e$message)
    })
  }
  
  # CSV fallback
  docs <- get_documents_from_csv(limit = 10000)
  if (column %in% names(docs)) {
    unique_vals <- unique(docs[[column]])
    unique_vals <- unique_vals[!is.na(unique_vals) & unique_vals != ""]
    return(sort(unique_vals))
  }
  
  return(character(0))
}

cat("✅ Database queries module loaded\n")