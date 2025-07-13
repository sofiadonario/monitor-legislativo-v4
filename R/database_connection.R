# Database Connection Module for Monitor Legislativo v4
# Connects to Railway PostgreSQL with updated 1,904 documents

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)

# Force refresh flag to ensure we get latest data
FORCE_REFRESH <- TRUE

# Helper function to create date parsing SQL
create_date_coalesce_sql <- function(prefix = "d") {
  # Handle empty prefix case
  table_prefix <- ifelse(nchar(prefix) > 0, paste0(prefix, "."), "")
  
  paste0("
    COALESCE(
      ", table_prefix, "data_publicacao,
      CASE 
        WHEN LENGTH(", table_prefix, "metadata->>'promulgation_date') = 10 AND ", table_prefix, "metadata->>'promulgation_date' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' 
          THEN (", table_prefix, "metadata->>'promulgation_date')::date
        WHEN LENGTH(", table_prefix, "metadata->>'promulgation_date') = 7 AND ", table_prefix, "metadata->>'promulgation_date' ~ '^[0-9]{4}-[0-9]{2}$' 
          THEN (", table_prefix, "metadata->>'promulgation_date' || '-01')::date
        WHEN LENGTH(", table_prefix, "metadata->>'promulgation_date') = 4 AND ", table_prefix, "metadata->>'promulgation_date' ~ '^[0-9]{4}$' 
          THEN (", table_prefix, "metadata->>'promulgation_date' || '-01-01')::date
        ELSE NULL
      END,
      CASE 
        WHEN LENGTH(", table_prefix, "metadata->>'publication_date') = 10 AND ", table_prefix, "metadata->>'publication_date' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' 
          THEN (", table_prefix, "metadata->>'publication_date')::date
        WHEN LENGTH(", table_prefix, "metadata->>'publication_date') = 7 AND ", table_prefix, "metadata->>'publication_date' ~ '^[0-9]{4}-[0-9]{2}$' 
          THEN (", table_prefix, "metadata->>'publication_date' || '-01')::date
        WHEN LENGTH(", table_prefix, "metadata->>'publication_date') = 4 AND ", table_prefix, "metadata->>'publication_date' ~ '^[0-9]{4}$' 
          THEN (", table_prefix, "metadata->>'publication_date' || '-01-01')::date
        ELSE NULL
      END,
      ", table_prefix, "created_at::date
    )
  ")
}

# Simpler fallback function for basic date handling
create_simple_date_coalesce_sql <- function(prefix = "d") {
  table_prefix <- ifelse(nchar(prefix) > 0, paste0(prefix, "."), "")
  paste0("COALESCE(", table_prefix, "data_publicacao, ", table_prefix, "created_at::date)")
}

# Global connection pool
db_pool <- NULL

#' Initialize database connection pool
#' @return TRUE if successful, FALSE otherwise
init_database <- function() {
  tryCatch({
    # Get DATABASE_URL from environment
    database_url <- Sys.getenv("DATABASE_URL")
    
    cat("🔄 Initializing database connection with FORCE_REFRESH =", FORCE_REFRESH, "\n")
    cat("DATABASE_URL present:", nchar(database_url) > 0, "\n")
    
    if (nchar(database_url) == 0) {
      warning("DATABASE_URL not found in environment variables")
      return(FALSE)
    }
    
    # Parse DATABASE_URL (format: postgresql://user:password@host:port/database)
    # Railway format: postgresql://postgres:password@host:port/railway
    parsed_url <- parse_database_url(database_url)
    
    if (is.null(parsed_url)) {
      warning("Failed to parse DATABASE_URL")
      return(FALSE)
    }
    
    cat("Connecting to database:\n")
    cat("  Host:", parsed_url$host, "\n")
    cat("  Port:", parsed_url$port, "\n")
    cat("  Database:", parsed_url$database, "\n")
    cat("  User:", parsed_url$user, "\n")
    
    # Create connection pool with shorter timeout for faster refresh
    db_pool <<- dbPool(
      drv = RPostgres::Postgres(),
      host = parsed_url$host,
      port = parsed_url$port,
      dbname = parsed_url$database,
      user = parsed_url$user,
      password = parsed_url$password,
      minSize = 1,
      maxSize = 5,
      idleTimeout = 300000  # 5 minutes for faster refresh
    )
    
    # Test connection
    test_result <- test_database_connection()
    if (test_result) {
      cat("✅ Database connection successful!\n")
      return(TRUE)
    } else {
      cat("❌ Database connection test failed\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("❌ Database initialization error:", e$message, "\n")
    return(FALSE)
  })
}

#' Parse DATABASE_URL into components
#' @param url The DATABASE_URL string
#' @return List with host, port, database, user, password or NULL if failed
parse_database_url <- function(url) {
  tryCatch({
    # Remove postgresql:// prefix
    url <- gsub("^postgresql://", "", url)
    
    # Split user:password@host:port/database
    if (grepl("@", url)) {
      parts <- strsplit(url, "@")[[1]]
      auth_part <- parts[1]
      host_part <- parts[2]
      
      # Extract user and password
      if (grepl(":", auth_part)) {
        auth_split <- strsplit(auth_part, ":")[[1]]
        user <- auth_split[1]
        password <- auth_split[2]
      } else {
        user <- auth_part
        password <- ""
      }
      
      # Extract host, port, and database
      if (grepl("/", host_part)) {
        host_db_split <- strsplit(host_part, "/")[[1]]
        host_port <- host_db_split[1]
        database <- host_db_split[2]
        
        if (grepl(":", host_port)) {
          host_port_split <- strsplit(host_port, ":")[[1]]
          host <- host_port_split[1]
          port <- as.integer(host_port_split[2])
        } else {
          host <- host_port
          port <- 5432L
        }
      } else {
        host <- host_part
        port <- 5432L
        database <- "postgres"
      }
      
      return(list(
        host = host,
        port = port,
        database = database,
        user = user,
        password = password
      ))
    }
    
    return(NULL)
  }, error = function(e) {
    cat("Error parsing DATABASE_URL:", e$message, "\n")
    return(NULL)
  })
}

#' Test database connection and verify tables
#' @return TRUE if successful, FALSE otherwise
test_database_connection <- function() {
  if (is.null(db_pool)) {
    cat("ERROR: Database pool is NULL\n")
    return(FALSE)
  }
  
  tryCatch({
    # Test basic connection first
    cat("Testing basic database connection...\n")
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Simple test query first
    simple_test <- dbGetQuery(conn, "SELECT 1 as test")
    cat("✅ Basic database connection successful\n")
    
    # Check if our tables exist
    tables <- dbListTables(conn)
    cat("Available tables:", paste(tables, collapse = ", "), "\n")
    
    # Check for the corrected tables/views
    corrected_tables <- c("lexml_parsed_enhanced_fixed", "documents", "lexml_documents_corrected")
    available_tables <- intersect(corrected_tables, tables)
    missing_tables <- setdiff(corrected_tables, tables)
    
    if (length(missing_tables) > 0) {
      cat("⚠️ Missing corrected tables:", paste(missing_tables, collapse = ", "), "\n")
    }
    
    # Check row counts and columns for available tables
    for (table in available_tables) {
      tryCatch({
        count <- as.numeric(dbGetQuery(conn, paste("SELECT COUNT(*) as count FROM", table))$count)
        cat("  ", table, ":", count, "rows\n")
        
        # Show column names and sample data
        if (table == "documents") {
          columns <- dbListFields(conn, table)
          cat("  ", table, "columns:", paste(columns, collapse = ", "), "\n")
          
          # Check for NULL titles with error handling
          tryCatch({
            null_check <- dbGetQuery(conn, "SELECT COUNT(*) as null_titles FROM documents WHERE titulo IS NULL")
            cat("    Documents with NULL titles:", null_check$null_titles, "\n")
          }, error = function(e2) {
            cat("    Error checking NULL titles:", e2$message, "\n")
          })
          
          # Get a sample row to see data structure
          tryCatch({
            sample <- dbGetQuery(conn, "SELECT * FROM documents LIMIT 1")
            if (nrow(sample) > 0) {
              cat("    Sample document structure:\n")
              for (col in names(sample)) {
                val <- sample[[col]][1]
                if (is.null(val)) {
                  cat("      ", col, ": NULL\n")
                } else if (is.na(val)) {
                  cat("      ", col, ": NA\n")
                } else {
                  cat("      ", col, ": ", substr(as.character(val), 1, 50), 
                      ifelse(nchar(as.character(val)) > 50, "...", ""), "\n")
                }
              }
            }
          }, error = function(e3) {
            cat("    Error getting sample data:", e3$message, "\n")
          })
        }
      }, error = function(e1) {
        cat("  ERROR checking table", table, ":", e1$message, "\n")
      })
    }
    
    # If documents table exists, always return TRUE to allow app to continue
    # The app can handle empty results
    result <- "documents" %in% tables
    cat("Connection test result:", result, "\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Database test error:", e$message, "\n")
    cat("Error class:", class(e), "\n")
    cat("Error details:\n")
    print(e)
    return(FALSE)
  })
}

#' Get all documents from the database with FORCE_REFRESH
#' @param limit Maximum number of documents to return (default: NULL for all)
#' @return Data frame with documents or NULL if error
get_documents <- function(limit = NULL) {
  if (is.null(db_pool)) {
    warning("Database not initialized")
    return(NULL)
  }
  
  cat("🔄 get_documents() called with FORCE_REFRESH =", FORCE_REFRESH, "\n")
  cat("DEBUG: get_documents() called with limit:", ifelse(is.null(limit), "NULL", limit), "\n")
  
  tryCatch({
    # First, let's check if the documents table has any data
    count_check <- dbGetQuery(db_pool, "SELECT COUNT(*) as total FROM documents")
    cat("DEBUG: Total documents in table:", count_check$total, "\n")
    
    # Check how many have non-null titles
    title_check <- dbGetQuery(db_pool, "SELECT COUNT(*) as with_title FROM documents WHERE titulo IS NOT NULL")
    cat("DEBUG: Documents with non-null titles:", title_check$with_title, "\n")
    
    # If no documents with titles, let's see what we have
    if (title_check$with_title == 0) {
      cat("WARNING: No documents with non-null titles found!\n")
      # Try to get some sample data anyway
      sample_query <- "SELECT id, titulo, tipo, estado, data_publicacao, metadata->>'promulgation_date' as promulgation_date, metadata->>'publication_date' as publication_date FROM documents LIMIT 5"
      sample_data <- dbGetQuery(db_pool, sample_query)
      cat("Sample data from documents table:\n")
      print(sample_data)
    }
    
    if (is.null(limit)) {
      # Try simple query first without complex joins or date parsing
      tryCatch({
        cat("DEBUG: Trying basic query without joins...\n")
        # First check if estado_codigo column exists
        has_estado_codigo <- tryCatch({
          dbGetQuery(db_pool, "SELECT estado_codigo FROM documents LIMIT 1")
          TRUE
        }, error = function(e) {
          cat("DEBUG: estado_codigo column not found, using estado instead\n")
          FALSE
        })
        
        if (has_estado_codigo) {
          query <- "
            SELECT 
              id,
              titulo,
              tipo,
              COALESCE(species, 'Não Classificado') as species,
              estado,
              CASE 
                WHEN estado_codigo IS NOT NULL THEN estado_codigo
                ELSE estado 
              END as estado_codigo,
              '' as municipio,
              COALESCE(data_publicacao, created_at::date) as enacting_date,
              url,
              urn
            FROM documents 
            WHERE titulo IS NOT NULL 
            ORDER BY COALESCE(data_publicacao, created_at::date) DESC NULLS LAST
          "
        } else {
          query <- "
            SELECT 
              id,
              titulo,
              tipo,
              COALESCE(species, 'Não Classificado') as species,
              estado,
              estado as estado_codigo,
              '' as municipio,
              COALESCE(data_publicacao, created_at::date) as enacting_date,
              url,
              urn
            FROM documents 
            WHERE titulo IS NOT NULL 
            ORDER BY COALESCE(data_publicacao, created_at::date) DESC NULLS LAST
          "
        }
        result <- dbGetQuery(db_pool, query)
        cat("DEBUG: Basic query returned", nrow(result), "rows\n")
        
        # If basic query fails, try even simpler
        if (nrow(result) == 0) {
          cat("DEBUG: Basic query returned 0, trying minimal query...\n")
          query <- "
            SELECT 
              id,
              titulo,
              tipo,
              estado,
              estado as estado_codigo,
              '' as municipio,
              created_at::date as enacting_date,
              url,
              urn
            FROM documents 
            ORDER BY id DESC
          "
          result <- dbGetQuery(db_pool, query)
          cat("DEBUG: Minimal query returned", nrow(result), "rows\n")
        }
      }, error = function(e) {
        cat("ERROR: All queries failed:", e$message, "\n")
        # Ultimate fallback: just get basic data
        cat("DEBUG: Trying ultimate fallback query...\n")
        query <- "SELECT id, titulo, tipo, estado FROM documents LIMIT 100"
        result <<- tryCatch({
          dbGetQuery(db_pool, query)
        }, error = function(e2) {
          cat("ERROR: Even fallback failed:", e2$message, "\n")
          data.frame()
        })
      })
    } else {
      # Limited query - use simple approach
      cat("DEBUG: Using limited query with limit:", limit, "\n")
      
      # Check if estado_codigo column exists for limited query too
      has_estado_codigo <- tryCatch({
        dbGetQuery(db_pool, "SELECT estado_codigo FROM documents LIMIT 1")
        TRUE
      }, error = function(e) {
        cat("DEBUG: estado_codigo column not found for limited query\n")
        FALSE
      })
      
      if (has_estado_codigo) {
        query <- paste0("
          SELECT 
            id,
            titulo,
            tipo,
            estado,
            CASE 
              WHEN estado_codigo IS NOT NULL THEN estado_codigo
              ELSE estado 
            END as estado_codigo,
            '' as municipio,
            COALESCE(data_publicacao, created_at::date) as enacting_date,
            url,
            urn
          FROM documents 
          WHERE titulo IS NOT NULL 
          ORDER BY COALESCE(data_publicacao, created_at::date) DESC NULLS LAST
          LIMIT ", limit
        )
      } else {
        query <- paste0("
          SELECT 
            id,
            titulo,
            tipo,
            estado,
            estado as estado_codigo,
            '' as municipio,
            COALESCE(data_publicacao, created_at::date) as enacting_date,
            url,
            urn
          FROM documents 
          WHERE titulo IS NOT NULL 
          ORDER BY COALESCE(data_publicacao, created_at::date) DESC NULLS LAST
          LIMIT ", limit
        )
      }
      result <- dbGetQuery(db_pool, query)
      cat("DEBUG: Limited query returned", nrow(result), "rows\n")
    }
    
    cat("DEBUG: Query executed, got", nrow(result), "rows\n")
    
    # Clean up the data
    if (nrow(result) > 0) {
      # Convert dates
      if ("enacting_date" %in% names(result)) {
        result$enacting_date <- as.Date(result$enacting_date)
      }
      
      # Clean up missing values
      result[is.na(result)] <- ""
      
      cat("Retrieved", nrow(result), "documents from database\n")
    } else {
      cat("WARNING: Query returned 0 rows\n")
      # If we got no results, let's try the simplest possible query
      cat("Trying ultra-simple fallback query...\n")
      fallback_query <- "
        SELECT 
          id,
          titulo,
          tipo,
          estado,
          estado as estado_codigo,
          '' as municipio,
          created_at::date as enacting_date,
          url,
          urn
        FROM documents 
        ORDER BY id DESC
        LIMIT 100
      "
      result <- dbGetQuery(db_pool, fallback_query)
      cat("Fallback query returned", nrow(result), "rows\n")
      
      if (nrow(result) > 0) {
        # Convert dates
        if ("enacting_date" %in% names(result)) {
          result$enacting_date <- as.Date(result$enacting_date)
        }
        result[is.na(result)] <- ""
      }
    }
    
    return(result)
    
  }, error = function(e) {
    cat("ERROR in get_documents():", e$message, "\n")
    cat("Stack trace:\n")
    print(e)
    return(NULL)
  })
}

#' Advanced search documents with filters
#' @param search_text Text to search for
#' @param document_types Vector of document types to filter (optional)
#' @param states Vector of states to filter (optional) 
#' @param date_from Start date for date range (optional)
#' @param date_to End date for date range (optional)
#' @param limit Maximum number of results
#' @return Data frame with search results
search_documents <- function(search_text = "", document_types = NULL, states = NULL, 
                            date_from = NULL, date_to = NULL, limit = 100) {
  if (is.null(db_pool)) {
    warning("Database not initialized")
    return(NULL)
  }
  
  tryCatch({
    # Build dynamic query with ranking
    has_search_text <- nchar(search_text) > 0
    date_sql <- create_date_coalesce_sql("d")
    
    if (has_search_text) {
      base_query <- paste0("
        SELECT 
          d.id,
          d.titulo,
          d.tipo,
          d.estado,
          COALESCE(lpe.municipality, 
                   d.metadata->>'municipality', 
                   CASE WHEN d.estado = 'SP' THEN 'São Paulo'
                        WHEN d.estado = 'RJ' THEN 'Rio de Janeiro'
                        ELSE NULL END) as municipio,
          (", date_sql, ") as enacting_date,
          d.url,
          d.urn,
          d.conteudo,
          CASE 
            WHEN d.titulo ILIKE $1 THEN 3
            WHEN d.conteudo ILIKE $1 THEN 1
            ELSE 0
          END as relevance_score
        FROM documents d
        LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn
        WHERE (d.titulo ILIKE $1 OR d.conteudo ILIKE $1)")
      
      params <- list(paste0("%", search_text, "%"))
      param_count <- 1
    } else {
      base_query <- paste0("
        SELECT 
          d.id,
          d.titulo,
          d.tipo,
          d.estado,
          COALESCE(lpe.municipality, 
                   d.metadata->>'municipality', 
                   CASE WHEN d.estado = 'SP' THEN 'São Paulo'
                        WHEN d.estado = 'RJ' THEN 'Rio de Janeiro'
                        ELSE NULL END) as municipio,
          (", date_sql, ") as enacting_date,
          d.url,
          d.urn,
          d.conteudo,
          0 as relevance_score
        FROM documents d
        LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn
        WHERE 1=1")
      
      params <- list()
      param_count <- 0
    }
    
    # Add document type filter
    if (!is.null(document_types) && length(document_types) > 0) {
      # Use simple string formatting for IN clauses (safer approach)
      quoted_types <- paste0("'", gsub("'", "''", document_types), "'", collapse = ", ")
      base_query <- paste(base_query, "AND d.tipo IN (", quoted_types, ")")
    }
    
    # Add state filter
    if (!is.null(states) && length(states) > 0) {
      # Use simple string formatting for IN clauses
      quoted_states <- paste0("'", gsub("'", "''", states), "'", collapse = ", ")
      base_query <- paste(base_query, "AND d.estado IN (", quoted_states, ")")
    }
    
    # Add date range filter - using enacting_date
    if (!is.null(date_from)) {
      param_count <- param_count + 1
      base_query <- paste(base_query, "AND (", date_sql, ") >= $", param_count, sep="")
      params[[param_count]] <- date_from
    }
    
    if (!is.null(date_to)) {
      param_count <- param_count + 1
      base_query <- paste(base_query, "AND (", date_sql, ") <= $", param_count, sep="")
      params[[param_count]] <- date_to
    }
    
    # Add ordering and limit - rank by relevance first, then by enacting_date
    param_count <- param_count + 1
    if (has_search_text) {
      base_query <- paste(base_query, "ORDER BY relevance_score DESC, (", date_sql, ") DESC NULLS LAST LIMIT $", param_count, sep="")
    } else {
      base_query <- paste(base_query, "ORDER BY (", date_sql, ") DESC NULLS LAST LIMIT $", param_count, sep="")
    }
    params[[param_count]] <- limit
    
    # Debug: print query for troubleshooting
    cat("DEBUG: Generated query:\n", base_query, "\n")
    cat("DEBUG: Query parameters count:", length(params), "\n")
    for (i in seq_along(params)) {
      cat("  Param", i, ":", as.character(params[[i]]), "\n")
    }
    
    # Execute query with error handling
    result <- tryCatch({
      dbGetQuery(db_pool, base_query, params = params)
    }, error = function(e) {
      cat("ERROR: Query execution failed:", e$message, "\n")
      cat("Query was:", base_query, "\n")
      return(data.frame())  # Return empty data frame on error
    })
    
    # Clean up the data
    if (nrow(result) > 0) {
      if ("enacting_date" %in% names(result)) {
        result$enacting_date <- as.Date(result$enacting_date)
      }
      result[is.na(result)] <- ""
      
      # Remove content and relevance score from display (too long for tables)
      if ("conteudo" %in% names(result)) {
        result$conteudo <- NULL
      }
      if ("relevance_score" %in% names(result)) {
        result$relevance_score <- NULL
      }
      
      search_desc <- paste(
        "text:", ifelse(nchar(search_text) > 0, search_text, "any"),
        "types:", ifelse(is.null(document_types), "any", paste(document_types, collapse=",")),
        "states:", ifelse(is.null(states), "any", paste(states, collapse=",")),
        "dates:", ifelse(is.null(date_from) && is.null(date_to), "any", 
                        paste(date_from, "to", date_to))
      )
      
      cat("Advanced search (", search_desc, ") returned", nrow(result), "documents\n")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("Error in advanced search:", e$message, "\n")
    return(NULL)
  })
}

#' Get available document types for filter
#' @return Vector of document types
get_document_types <- function() {
  if (is.null(db_pool)) {
    return(c("lei", "decreto", "portaria"))
  }
  
  tryCatch({
    result <- dbGetQuery(db_pool, "
      SELECT DISTINCT tipo 
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != '' 
      ORDER BY tipo
    ")
    
    if (nrow(result) > 0) {
      cat("DEBUG: Found document types:", paste(result$tipo, collapse = ", "), "\n")
      return(result$tipo)
    } else {
      cat("DEBUG: No document types found in database, using defaults\n")
      return(c("lei", "decreto", "portaria"))
    }
    
  }, error = function(e) {
    cat("ERROR getting document types:", e$message, "\n")
    return(c("lei", "decreto", "portaria"))
  })
}

#' Get available states for filter
#' @return Vector of states
get_states <- function() {
  if (is.null(db_pool)) {
    return(c("SP", "RJ", "MG", "RS"))
  }
  
  tryCatch({
    result <- dbGetQuery(db_pool, "
      SELECT DISTINCT estado 
      FROM documents 
      WHERE estado IS NOT NULL AND estado != '' 
      ORDER BY estado
    ")
    
    if (nrow(result) > 0) {
      cat("DEBUG: Found states:", paste(result$estado, collapse = ", "), "\n")
      return(result$estado)
    } else {
      cat("DEBUG: No states found in database, using defaults\n")
      return(c("SP", "RJ", "MG", "RS"))
    }
    
  }, error = function(e) {
    cat("ERROR getting states:", e$message, "\n")
    return(c("SP", "RJ", "MG", "RS"))
  })
}

#' Get document statistics
#' @return List with various statistics
get_document_stats <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_documents = 0,
      document_types = data.frame(),
      states = data.frame(),
      connection_status = "No database connection"
    ))
  }
  
  tryCatch({
    # Total documents
    total <- as.numeric(dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count)
    
    # Document types
    types <- dbGetQuery(db_pool, "
      SELECT tipo, COUNT(*) as count 
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != ''
      GROUP BY tipo 
      ORDER BY count DESC 
      LIMIT 10
    ")
    
    # States distribution
    states <- dbGetQuery(db_pool, "
      SELECT estado, COUNT(*) as count 
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado 
      ORDER BY count DESC 
      LIMIT 10
    ")
    
    return(list(
      total_documents = total,
      document_types = types,
      states = states,
      connection_status = "Connected"
    ))
    
  }, error = function(e) {
    cat("Error getting statistics:", e$message, "\n")
    return(list(
      total_documents = 0,
      document_types = data.frame(),
      states = data.frame(),
      connection_status = paste("Error:", e$message)
    ))
  })
}

#' Get search analytics and statistics
#' @return List with search-related statistics
get_search_analytics <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_day = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      documents_by_species = data.frame(),
      documents_by_gender_species = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  }
  
  cat("DEBUG: get_search_analytics() called\n")
  
  tryCatch({
    # Total documents
    total <- as.numeric(dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count)
    cat("DEBUG: Total documents found:", total, "\n")
    
    # Documents by year - try enhanced table first, fallback to simple approach
    by_year <- tryCatch({
      dbGetQuery(db_pool, "
        SELECT 
          EXTRACT(YEAR FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)) as year,
          COUNT(*) as count
        FROM documents d
        LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn
        WHERE COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date) IS NOT NULL
        GROUP BY EXTRACT(YEAR FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date))
        ORDER BY year DESC
        LIMIT 10
      ")
    }, error = function(e) {
      cat("DEBUG: Enhanced table query failed, using fallback:", e$message, "\n")
      dbGetQuery(db_pool, "
        SELECT 
          EXTRACT(YEAR FROM COALESCE(d.data_publicacao, d.created_at::date)) as year,
          COUNT(*) as count
        FROM documents d
        WHERE COALESCE(d.data_publicacao, d.created_at::date) IS NOT NULL
        GROUP BY EXTRACT(YEAR FROM COALESCE(d.data_publicacao, d.created_at::date))
        ORDER BY year DESC
        LIMIT 10
      ")
    })
    cat("DEBUG: Year query got", nrow(by_year), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_year) > 0) {
      by_year$count <- as.numeric(by_year$count)
      by_year$year <- as.numeric(by_year$year)
      cat("DEBUG: Years data:", paste(by_year$year, collapse = ", "), "\n")
    } else {
      cat("DEBUG: No year data found\n")
    }
    
    # Documents by month - try enhanced table first, fallback to simple approach
    by_month <- tryCatch({
      dbGetQuery(db_pool, "
        SELECT 
          EXTRACT(YEAR FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)) as year,
          EXTRACT(MONTH FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)) as month,
          COUNT(*) as count,
          TO_CHAR(COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date), 'YYYY-MM') as year_month
        FROM documents d
        LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn
        WHERE COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date) IS NOT NULL
        GROUP BY EXTRACT(YEAR FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)), 
                 EXTRACT(MONTH FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)),
                 TO_CHAR(COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date), 'YYYY-MM')
        ORDER BY year DESC, month DESC
        LIMIT 12
      ")
    }, error = function(e) {
      cat("DEBUG: Enhanced table query failed, using fallback:", e$message, "\n")
      dbGetQuery(db_pool, "
        SELECT 
          EXTRACT(YEAR FROM COALESCE(d.data_publicacao, d.created_at::date)) as year,
          EXTRACT(MONTH FROM COALESCE(d.data_publicacao, d.created_at::date)) as month,
          COUNT(*) as count,
          TO_CHAR(COALESCE(d.data_publicacao, d.created_at::date), 'YYYY-MM') as year_month
        FROM documents d
        WHERE COALESCE(d.data_publicacao, d.created_at::date) IS NOT NULL
        GROUP BY EXTRACT(YEAR FROM COALESCE(d.data_publicacao, d.created_at::date)), 
                 EXTRACT(MONTH FROM COALESCE(d.data_publicacao, d.created_at::date)),
                 TO_CHAR(COALESCE(d.data_publicacao, d.created_at::date), 'YYYY-MM')
        ORDER BY year DESC, month DESC
        LIMIT 12
      ")
    })
    cat("DEBUG: Month query got", nrow(by_month), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_month) > 0) {
      by_month$count <- as.numeric(by_month$count)
      by_month$year <- as.numeric(by_month$year)
      by_month$month <- as.numeric(by_month$month)
    }
    
    # Documents by day - try enhanced table first, fallback to simple approach
    by_day <- tryCatch({
      dbGetQuery(db_pool, "
        SELECT 
          COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)::date as day,
          COUNT(*) as count,
          TO_CHAR(COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date), 'YYYY-MM-DD') as formatted_date
        FROM documents d
        LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn
        WHERE COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date) IS NOT NULL
        GROUP BY COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)::date,
                 TO_CHAR(COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date), 'YYYY-MM-DD')
        ORDER BY day DESC
        LIMIT 30
      ")
    }, error = function(e) {
      cat("DEBUG: Enhanced table query failed, using fallback:", e$message, "\n")
      dbGetQuery(db_pool, "
        SELECT 
          COALESCE(d.data_publicacao, d.created_at::date)::date as day,
          COUNT(*) as count,
          TO_CHAR(COALESCE(d.data_publicacao, d.created_at::date), 'YYYY-MM-DD') as formatted_date
        FROM documents d
        WHERE COALESCE(d.data_publicacao, d.created_at::date) IS NOT NULL
        GROUP BY COALESCE(d.data_publicacao, d.created_at::date)::date,
                 TO_CHAR(COALESCE(d.data_publicacao, d.created_at::date), 'YYYY-MM-DD')
        ORDER BY day DESC
        LIMIT 30
      ")
    })
    cat("DEBUG: Day query got", nrow(by_day), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_day) > 0) {
      by_day$count <- as.numeric(by_day$count)
      by_day$day <- as.Date(by_day$day)
    }
    
    # Documents by state (top 10)
    by_state <- dbGetQuery(db_pool, "
      SELECT 
        estado,
        COUNT(*) as count
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado
      ORDER BY count DESC
      LIMIT 10
    ")
    cat("DEBUG: State query got", nrow(by_state), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_state) > 0) {
      by_state$count <- as.numeric(by_state$count)
    }
    
    # Documents by type (gender)
    by_type <- dbGetQuery(db_pool, "
      SELECT 
        tipo,
        COUNT(*) as count
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != ''
      GROUP BY tipo
      ORDER BY count DESC
    ")
    cat("DEBUG: Type query got", nrow(by_type), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_type) > 0) {
      by_type$count <- as.numeric(by_type$count)
    }
    
    # Documents by species
    by_species <- dbGetQuery(db_pool, "
      SELECT 
        species,
        tipo as gender,
        COUNT(*) as count
      FROM documents 
      WHERE species IS NOT NULL AND species != ''
      GROUP BY species, tipo
      ORDER BY count DESC
    ")
    cat("DEBUG: Species query got", nrow(by_species), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_species) > 0) {
      by_species$count <- as.numeric(by_species$count)
    }
    
    # Documents by gender and species combined
    by_gender_species <- dbGetQuery(db_pool, "
      SELECT 
        tipo as gender,
        species,
        COUNT(*) as count
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != '' AND species IS NOT NULL AND species != ''
      GROUP BY tipo, species
      ORDER BY tipo, count DESC
    ")
    cat("DEBUG: Gender-Species query got", nrow(by_gender_species), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_gender_species) > 0) {
      by_gender_species$count <- as.numeric(by_gender_species$count)
    }
    
    # Recent documents - try enhanced table first, fallback to simple approach
    recent <- tryCatch({
      dbGetQuery(db_pool, "
        SELECT 
          d.titulo,
          d.tipo,
          d.species,
          d.estado,
          COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date) as enacting_date
        FROM documents d
        LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn
        WHERE COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date) IS NOT NULL
          AND d.titulo IS NOT NULL
        ORDER BY COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date) DESC
        LIMIT 10
      ")
    }, error = function(e) {
      cat("DEBUG: Enhanced table query failed, using fallback:", e$message, "\n")
      dbGetQuery(db_pool, "
        SELECT 
          d.titulo,
          d.tipo,
          d.species,
          d.estado,
          COALESCE(d.data_publicacao, d.created_at::date) as enacting_date
        FROM documents d
        WHERE COALESCE(d.data_publicacao, d.created_at::date) IS NOT NULL
          AND d.titulo IS NOT NULL
        ORDER BY COALESCE(d.data_publicacao, d.created_at::date) DESC
        LIMIT 10
      ")
    })
    cat("DEBUG: Recent query got", nrow(recent), "rows\n")
    
    # Date range - try enhanced table first, fallback to simple approach
    date_range <- tryCatch({
      dbGetQuery(db_pool, "
        SELECT 
          MIN(COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)) as min_date,
          MAX(COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date)) as max_date
        FROM documents d
        LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn
        WHERE COALESCE(lpe.promulgation_date::date, d.data_publicacao, d.created_at::date) IS NOT NULL
      ")
    }, error = function(e) {
      cat("DEBUG: Enhanced table query failed, using fallback:", e$message, "\n")
      dbGetQuery(db_pool, "
        SELECT 
          MIN(COALESCE(d.data_publicacao, d.created_at::date)) as min_date,
          MAX(COALESCE(d.data_publicacao, d.created_at::date)) as max_date
        FROM documents d
        WHERE COALESCE(d.data_publicacao, d.created_at::date) IS NOT NULL
      ")
    })
    cat("DEBUG: Date range query completed\n")
    
    result <- list(
      total_documents = total,
      documents_by_year = by_year,
      documents_by_month = by_month,
      documents_by_day = by_day,
      documents_by_state = by_state,
      documents_by_type = by_type,
      documents_by_species = by_species,
      documents_by_gender_species = by_gender_species,
      recent_documents = recent,
      date_range = list(
        min = date_range$min_date,
        max = date_range$max_date
      )
    )
    
    cat("DEBUG: Analytics completed successfully\n")
    return(result)
    
  }, error = function(e) {
    cat("ERROR in get_search_analytics():", e$message, "\n")
    cat("Stack trace:\n")
    print(e)
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_day = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      documents_by_species = data.frame(),
      documents_by_gender_species = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  })
}

#' Highlight search terms in text
#' @param text The text to highlight
#' @param search_terms Vector of terms to highlight
#' @return HTML string with highlighted terms
highlight_search_terms <- function(text, search_terms) {
  if (is.null(search_terms) || length(search_terms) == 0 || is.null(text) || nchar(text) == 0) {
    return(text)
  }
  
  result <- text
  for (term in search_terms) {
    if (nchar(term) > 0) {
      # Case-insensitive replacement with HTML highlighting
      pattern <- paste0("(", term, ")")
      replacement <- '<mark style="background-color: #ffff00; padding: 0 2px;">\\1</mark>'
      result <- gsub(pattern, replacement, result, ignore.case = TRUE)
    }
  }
  
  return(result)
}

#' Force refresh database connection and clear cache
force_refresh_database <- function() {
  cat("🔄 Force refreshing database connection...\n")
  
  # Close existing connection
  if (!is.null(db_pool)) {
    poolClose(db_pool)
    db_pool <<- NULL
    cat("Closed existing database pool\n")
  }
  
  # Clear any cached data
  if (exists("values", envir = .GlobalEnv)) {
    rm(list = c("current_documents", "analytics_data", "geographic_data"), 
       envir = get("values", envir = .GlobalEnv), inherits = TRUE)
    cat("Cleared cached data\n")
  }
  
  # Reinitialize connection
  result <- init_database()
  if (result) {
    cat("✅ Database connection refreshed successfully\n")
  } else {
    cat("❌ Failed to refresh database connection\n")
  }
  
  return(result)
}

#' Close database connection pool
cleanup_database <- function() {
  if (!is.null(db_pool)) {
    poolClose(db_pool)
    db_pool <<- NULL
    cat("Database connection pool closed\n")
  }
}