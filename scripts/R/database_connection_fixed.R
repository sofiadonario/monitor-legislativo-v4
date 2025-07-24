# Fixed Database Connection Module for Monitor Legislativo v4
# Works with the actual lexml_* tables structure

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)
library(jsonlite)

# Force refresh flag
FORCE_REFRESH <- TRUE

# Global connection pool
db_pool <- NULL

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

#' Initialize database connection pool
#' @return TRUE if successful, FALSE otherwise
init_database <- function() {
  tryCatch({
    # Get DATABASE_URL from environment, with fallback
    database_url <- Sys.getenv("DATABASE_URL")
    
    cat("🔄 Initializing database connection...\n")
    cat("DATABASE_URL present:", nchar(database_url) > 0, "\n")
    
    if (nchar(database_url) == 0) {
      # Fallback to Railway PostgreSQL URL (internal network)
      database_url <- "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway"
      cat("⚠️ Using fallback DATABASE_URL (internal Railway network)\n")
    }
    
    # Parse DATABASE_URL
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
    
    # Create connection pool
    db_pool <<- dbPool(
      drv = RPostgres::Postgres(),
      host = parsed_url$host,
      port = parsed_url$port,
      dbname = parsed_url$database,
      user = parsed_url$user,
      password = parsed_url$password,
      minSize = 1,
      maxSize = 5,
      idleTimeout = 300000
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

#' Test database connection and verify tables
#' @return TRUE if successful, FALSE otherwise
test_database_connection <- function() {
  if (is.null(db_pool)) {
    cat("ERROR: Database pool is NULL\n")
    return(FALSE)
  }
  
  tryCatch({
    cat("Testing basic database connection...\n")
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Simple test query
    simple_test <- dbGetQuery(conn, "SELECT 1 as test")
    cat("✅ Basic database connection successful\n")
    
    # Check if our tables exist
    tables <- dbListTables(conn)
    cat("Available tables:", paste(tables, collapse = ", "), "\n")
    
    # Check for lexml tables
    lexml_tables <- grep("^lexml_", tables, value = TRUE)
    cat("Found", length(lexml_tables), "lexml tables\n")
    
    # Check if documents view exists
    has_documents_view <- "documents" %in% tables
    
    if (!has_documents_view && length(lexml_tables) > 0) {
      cat("⚠️ Documents view not found, but lexml tables exist\n")
      cat("   Run create_documents_view.sql to create the unified view\n")
    }
    
    # Return TRUE if we have either the view or the tables
    result <- has_documents_view || length(lexml_tables) > 0
    cat("Connection test result:", result, "\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Database test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Get all documents from the database
#' @param limit Maximum number of documents to return
#' @return Data frame with documents or NULL if error
get_documents <- function(limit = NULL) {
  if (is.null(db_pool)) {
    warning("Database not initialized")
    return(NULL)
  }
  
  cat("🔄 Loading documents from database...\n")
  
  tryCatch({
    # First check if documents view exists
    tables <- dbListTables(db_pool)
    
    if ("documents" %in% tables) {
      # Use the unified view
      query <- "
        SELECT 
          id,
          titulo,
          tipo,
          COALESCE(species, 'Não Classificado') as species,
          estado,
          estado_codigo,
          municipality as municipio,
          data_publicacao as enacting_date,
          url,
          urn,
          conteudo,
          document_summary,
          document_type_full,
          search_term
        FROM documents 
        WHERE titulo IS NOT NULL 
        ORDER BY data_publicacao DESC NULLS LAST
      "
      
      if (!is.null(limit)) {
        query <- paste0(query, " LIMIT ", limit)
      }
      
      result <- dbGetQuery(db_pool, query)
      
    } else {
      # Fallback: query lexml tables directly
      cat("Documents view not found, querying lexml tables directly...\n")
      
      # Get all lexml tables
      lexml_tables <- grep("^lexml_", tables, value = TRUE)
      
      if (length(lexml_tables) == 0) {
        cat("No lexml tables found!\n")
        return(data.frame())
      }
      
      # Build union query
      union_parts <- lapply(lexml_tables, function(table) {
        sprintf("
          SELECT 
            id,
            titulo,
            tipo,
            'Não Classificado' as species,
            CASE 
              WHEN jurisdicao = 'federal' THEN 'BR'
              WHEN jurisdicao = 'estadual' THEN 'Estado'
              ELSE COALESCE(jurisdicao, 'BR')
            END as estado,
            CASE 
              WHEN jurisdicao = 'federal' THEN 'BR'
              WHEN jurisdicao = 'estadual' THEN 'Estado'
              ELSE COALESCE(jurisdicao, 'BR')
            END as estado_codigo,
            COALESCE(localidade, '') as municipio,
            data as enacting_date,
            url,
            urn,
            COALESCE(ementa, '') as conteudo,
            COALESCE(ementa, '') as document_summary,
            categoria || ' - ' || modal as document_type_full,
            termo_busca as search_term
          FROM %s
          WHERE titulo IS NOT NULL
        ", table)
      })
      
      query <- paste(union_parts, collapse = " UNION ALL ")
      query <- paste0("SELECT * FROM (", query, ") AS all_docs ORDER BY enacting_date DESC NULLS LAST")
      
      if (!is.null(limit)) {
        query <- paste0(query, " LIMIT ", limit)
      }
      
      result <- dbGetQuery(db_pool, query)
    }
    
    cat("Retrieved", nrow(result), "documents from database\n")
    
    # Clean up the data
    if (nrow(result) > 0) {
      # Convert dates
      if ("enacting_date" %in% names(result)) {
        result$enacting_date <- as.Date(result$enacting_date)
      }
      
      # Clean up missing values
      result[is.na(result)] <- ""
    }
    
    return(result)
    
  }, error = function(e) {
    cat("ERROR in get_documents():", e$message, "\n")
    return(NULL)
  })
}

#' Search documents with filters
#' @param search_text Text to search for
#' @param document_types Vector of document types to filter
#' @param states Vector of states to filter
#' @param date_from Start date for date range
#' @param date_to End date for date range
#' @param limit Maximum number of results
#' @return Data frame with search results
search_documents <- function(search_text = "", document_types = NULL, states = NULL, 
                           date_from = NULL, date_to = NULL, limit = 100) {
  if (is.null(db_pool)) {
    warning("Database not initialized")
    return(NULL)
  }
  
  tryCatch({
    # Check if documents view exists
    tables <- dbListTables(db_pool)
    use_view <- "documents" %in% tables
    
    if (use_view) {
      # Build query for documents view
      base_query <- "
        SELECT 
          id,
          titulo,
          tipo,
          estado,
          municipality as municipio,
          data_publicacao as enacting_date,
          url,
          urn,
          conteudo
        FROM documents
        WHERE 1=1
      "
      
      # Add search condition
      if (nchar(search_text) > 0) {
        base_query <- paste0(base_query, " AND (titulo ILIKE '%", search_text, "%' OR conteudo ILIKE '%", search_text, "%')")
      }
      
      # Add filters
      if (!is.null(document_types) && length(document_types) > 0) {
        quoted_types <- paste0("'", gsub("'", "''", document_types), "'", collapse = ", ")
        base_query <- paste(base_query, "AND tipo IN (", quoted_types, ")")
      }
      
      if (!is.null(states) && length(states) > 0) {
        quoted_states <- paste0("'", gsub("'", "''", states), "'", collapse = ", ")
        base_query <- paste(base_query, "AND estado IN (", quoted_states, ")")
      }
      
      if (!is.null(date_from)) {
        base_query <- paste0(base_query, " AND data_publicacao >= '", date_from, "'")
      }
      
      if (!is.null(date_to)) {
        base_query <- paste0(base_query, " AND data_publicacao <= '", date_to, "'")
      }
      
      # Add ordering and limit
      base_query <- paste0(base_query, " ORDER BY data_publicacao DESC NULLS LAST LIMIT ", limit)
      
    } else {
      # Fallback: query lexml tables directly
      lexml_tables <- grep("^lexml_", tables, value = TRUE)
      
      if (length(lexml_tables) == 0) {
        return(data.frame())
      }
      
      # Build union query with filters
      union_parts <- lapply(lexml_tables, function(table) {
        query_part <- sprintf("
          SELECT 
            id,
            titulo,
            tipo,
            CASE 
              WHEN jurisdicao = 'federal' THEN 'BR'
              ELSE COALESCE(jurisdicao, 'BR')
            END as estado,
            COALESCE(localidade, '') as municipio,
            data as enacting_date,
            url,
            urn,
            COALESCE(ementa, '') as conteudo
          FROM %s
          WHERE titulo IS NOT NULL
        ", table)
        
        if (nchar(search_text) > 0) {
          query_part <- paste0(query_part, " AND (titulo ILIKE '%", search_text, "%' OR ementa ILIKE '%", search_text, "%')")
        }
        
        query_part
      })
      
      base_query <- paste(union_parts, collapse = " UNION ALL ")
      base_query <- paste0("SELECT * FROM (", base_query, ") AS all_docs")
      
      # Add filters to the outer query
      if (!is.null(document_types) && length(document_types) > 0) {
        quoted_types <- paste0("'", gsub("'", "''", document_types), "'", collapse = ", ")
        base_query <- paste(base_query, "WHERE tipo IN (", quoted_types, ")")
      }
      
      base_query <- paste0(base_query, " ORDER BY enacting_date DESC NULLS LAST LIMIT ", limit)
    }
    
    # Execute query
    result <- dbGetQuery(db_pool, base_query)
    
    # Clean up the data
    if (nrow(result) > 0) {
      if ("enacting_date" %in% names(result)) {
        result$enacting_date <- as.Date(result$enacting_date)
      }
      result[is.na(result)] <- ""
      
      # Remove content from display
      if ("conteudo" %in% names(result)) {
        result$conteudo <- NULL
      }
    }
    
    cat("Search returned", nrow(result), "documents\n")
    return(result)
    
  }, error = function(e) {
    cat("Error in search:", e$message, "\n")
    return(NULL)
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
    tables <- dbListTables(db_pool)
    
    if ("documents" %in% tables) {
      # Use documents view
      total <- as.numeric(dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count)
      
      types <- dbGetQuery(db_pool, "
        SELECT tipo, COUNT(*) as count 
        FROM documents 
        WHERE tipo IS NOT NULL
        GROUP BY tipo 
        ORDER BY count DESC
      ")
      
      states <- dbGetQuery(db_pool, "
        SELECT estado, COUNT(*) as count 
        FROM documents 
        WHERE estado IS NOT NULL
        GROUP BY estado 
        ORDER BY count DESC
      ")
      
    } else {
      # Use lexml tables
      lexml_tables <- grep("^lexml_", tables, value = TRUE)
      
      if (length(lexml_tables) == 0) {
        return(list(
          total_documents = 0,
          document_types = data.frame(),
          states = data.frame(),
          connection_status = "No lexml tables found"
        ))
      }
      
      # Get total count
      total <- 0
      for (table in lexml_tables) {
        count <- as.numeric(dbGetQuery(db_pool, paste("SELECT COUNT(*) as count FROM", table))$count)
        total <- total + count
      }
      
      # Get aggregated stats
      types <- data.frame(tipo = character(), count = numeric())
      states <- data.frame(estado = character(), count = numeric())
    }
    
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

#' Get search analytics
#' @return List with search-related statistics
get_search_analytics <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      recent_documents = data.frame()
    ))
  }
  
  tryCatch({
    tables <- dbListTables(db_pool)
    
    if ("documents" %in% tables) {
      # Use documents view for analytics
      total <- as.numeric(dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count)
      
      by_year <- dbGetQuery(db_pool, "
        SELECT 
          EXTRACT(YEAR FROM data_publicacao) as year,
          COUNT(*) as count
        FROM documents
        WHERE data_publicacao IS NOT NULL
        GROUP BY EXTRACT(YEAR FROM data_publicacao)
        ORDER BY year DESC
        LIMIT 10
      ")
      
      by_month <- dbGetQuery(db_pool, "
        SELECT 
          EXTRACT(YEAR FROM data_publicacao) as year,
          EXTRACT(MONTH FROM data_publicacao) as month,
          COUNT(*) as count
        FROM documents
        WHERE data_publicacao IS NOT NULL
        GROUP BY EXTRACT(YEAR FROM data_publicacao), EXTRACT(MONTH FROM data_publicacao)
        ORDER BY year DESC, month DESC
        LIMIT 12
      ")
      
      by_state <- dbGetQuery(db_pool, "
        SELECT estado, COUNT(*) as count
        FROM documents
        WHERE estado IS NOT NULL
        GROUP BY estado
        ORDER BY count DESC
        LIMIT 10
      ")
      
      by_type <- dbGetQuery(db_pool, "
        SELECT tipo, COUNT(*) as count
        FROM documents
        WHERE tipo IS NOT NULL
        GROUP BY tipo
        ORDER BY count DESC
      ")
      
      recent <- dbGetQuery(db_pool, "
        SELECT titulo, tipo, estado, data_publicacao as enacting_date
        FROM documents
        WHERE titulo IS NOT NULL
        ORDER BY data_publicacao DESC NULLS LAST
        LIMIT 10
      ")
      
    } else {
      # Fallback to empty data
      total <- 0
      by_year <- data.frame()
      by_month <- data.frame()
      by_state <- data.frame()
      by_type <- data.frame()
      recent <- data.frame()
    }
    
    # Convert integer64 to numeric
    if (nrow(by_year) > 0) {
      by_year$count <- as.numeric(by_year$count)
      by_year$year <- as.numeric(by_year$year)
    }
    
    if (nrow(by_month) > 0) {
      by_month$count <- as.numeric(by_month$count)
      by_month$year <- as.numeric(by_month$year)
      by_month$month <- as.numeric(by_month$month)
    }
    
    if (nrow(by_state) > 0) {
      by_state$count <- as.numeric(by_state$count)
    }
    
    if (nrow(by_type) > 0) {
      by_type$count <- as.numeric(by_type$count)
    }
    
    return(list(
      total_documents = total,
      documents_by_year = by_year,
      documents_by_month = by_month,
      documents_by_state = by_state,
      documents_by_type = by_type,
      documents_by_species = data.frame(),  # Not applicable for this structure
      documents_by_gender_species = data.frame(),  # Not applicable
      recent_documents = recent,
      documents_by_day = data.frame()  # Could be added if needed
    ))
    
  }, error = function(e) {
    cat("Error in get_search_analytics():", e$message, "\n")
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      documents_by_species = data.frame(),
      documents_by_gender_species = data.frame(),
      recent_documents = data.frame(),
      documents_by_day = data.frame()
    ))
  })
}

#' Get document types for filter
#' @return Vector of document types
get_document_types <- function() {
  if (is.null(db_pool)) {
    return(c("legislacao", "jurisprudencia", "doutrina", "proposicoes", "outros"))
  }
  
  tryCatch({
    tables <- dbListTables(db_pool)
    
    # Extract types from table names
    lexml_tables <- grep("^lexml_", tables, value = TRUE)
    
    if (length(lexml_tables) > 0) {
      # Extract category names
      categories <- unique(gsub("^lexml_|_.*$", "", lexml_tables))
      return(sort(categories))
    }
    
    return(c("legislacao", "jurisprudencia", "doutrina", "proposicoes", "outros"))
    
  }, error = function(e) {
    cat("ERROR getting document types:", e$message, "\n")
    return(c("legislacao", "jurisprudencia", "doutrina", "proposicoes", "outros"))
  })
}

#' Get states for filter with proper names and coordinates
#' @return Data frame with state info
get_states <- function() {
  if (is.null(db_pool)) {
    return(data.frame(abbrev = c("BR"), name = c("Federal"), count = c(0)))
  }
  
  tryCatch({
    # Get state counts from documents
    state_counts <- dbGetQuery(db_pool, "
      SELECT 
        d.estado as abbrev,
        COUNT(*) as count
      FROM documents d
      WHERE d.estado IS NOT NULL 
      GROUP BY d.estado
      ORDER BY count DESC
    ")
    
    # Join with Brazilian states reference for proper names
    if ("brazilian_states" %in% dbListTables(db_pool)) {
      result <- dbGetQuery(db_pool, "
        SELECT 
          bs.abbrev,
          bs.name,
          bs.region,
          bs.lat,
          bs.lng,
          COALESCE(sc.count, 0) as count
        FROM brazilian_states bs
        LEFT JOIN (
          SELECT estado as abbrev, COUNT(*) as count
          FROM documents 
          WHERE estado IS NOT NULL
          GROUP BY estado
        ) sc ON bs.abbrev = sc.abbrev
        WHERE COALESCE(sc.count, 0) > 0
        ORDER BY count DESC
      ")
      
      if (nrow(result) > 0) {
        return(result)
      }
    }
    
    # Fallback: return just the counts with abbreviations
    return(state_counts)
    
  }, error = function(e) {
    cat("ERROR getting states:", e$message, "\n")
    return(data.frame(abbrev = c("BR"), name = c("Federal"), count = c(0)))
  })
}

#' Get map data for Interactive Map 1 (from lexml_documents)
#' @return Data frame with state data for mapping
get_map1_data <- function() {
  if (is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    # Get data from lexml_documents table
    result <- dbGetQuery(db_pool, "
      SELECT 
        bs.abbrev,
        bs.name,
        bs.region,
        bs.capital,
        bs.lat,
        bs.lng,
        COALESCE(doc_counts.total_docs, 0) as total_docs
      FROM brazilian_states bs
      LEFT JOIN (
        SELECT 
          estado as abbrev,
          COUNT(*) as total_docs
        FROM lexml_documents 
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado
      ) doc_counts ON bs.abbrev = doc_counts.abbrev
      WHERE COALESCE(doc_counts.total_docs, 0) > 0
      ORDER BY total_docs DESC
    ")
    
    return(result)
    
  }, error = function(e) {
    cat("ERROR getting map1 data:", e$message, "\n")
    return(data.frame())
  })
}

#' Get map data for Interactive Map 2 (Legislation tables)
#' @return Data frame with state data for legislation
get_map2_data <- function() {
  if (is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    # Get data from all lexml_legislacao_* tables
    result <- dbGetQuery(db_pool, "
      SELECT 
        bs.abbrev,
        bs.name,
        bs.region,
        bs.capital,
        bs.lat,
        bs.lng,
        COALESCE(doc_counts.total_docs, 0) as total_docs
      FROM brazilian_states bs
      LEFT JOIN (
        SELECT 
          estado as abbrev,
          COUNT(*) as total_docs
        FROM (
          SELECT estado FROM lexml_legislacao_aereo WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_legislacao_geral WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_legislacao_maritimo WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_legislacao_rodoviario WHERE estado IS NOT NULL AND estado != ''
        ) combined
        GROUP BY estado
      ) doc_counts ON bs.abbrev = doc_counts.abbrev
      WHERE COALESCE(doc_counts.total_docs, 0) > 0
      ORDER BY total_docs DESC
    ")
    
    return(result)
    
  }, error = function(e) {
    cat("ERROR getting map2 data:", e$message, "\n")
    return(data.frame())
  })
}

#' Get map data for Interactive Map 3 (Jurisprudence + Propositions)
#' @return Data frame with state data for jurisprudence and propositions
get_map3_data <- function() {
  if (is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    # Get data from all lexml_jurisprudencia_* and lexml_proposicoes_* tables
    result <- dbGetQuery(db_pool, "
      SELECT 
        bs.abbrev,
        bs.name,
        bs.region,
        bs.capital,
        bs.lat,
        bs.lng,
        COALESCE(doc_counts.total_docs, 0) as total_docs
      FROM brazilian_states bs
      LEFT JOIN (
        SELECT 
          estado as abbrev,
          COUNT(*) as total_docs
        FROM (
          SELECT estado FROM lexml_jurisprudencia_aereo WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_jurisprudencia_geral WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_jurisprudencia_maritimo WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_jurisprudencia_rodoviario WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_proposicoes_aereo WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_proposicoes_geral WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_proposicoes_maritimo WHERE estado IS NOT NULL AND estado != ''
          UNION ALL
          SELECT estado FROM lexml_proposicoes_rodoviario WHERE estado IS NOT NULL AND estado != ''
        ) combined
        GROUP BY estado
      ) doc_counts ON bs.abbrev = doc_counts.abbrev
      WHERE COALESCE(doc_counts.total_docs, 0) > 0
      ORDER BY total_docs DESC
    ")
    
    return(result)
    
  }, error = function(e) {
    cat("ERROR getting map3 data:", e$message, "\n")
    return(data.frame())
  })
}

#' Get dashboard metrics from lexml_documents
#' @return List with dashboard statistics
get_lexml_dashboard_metrics <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_docs = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      date_range = "No data"
    ))
  }
  
  tryCatch({
    # Get metrics from lexml_documents table
    metrics <- dbGetQuery(db_pool, "
      SELECT 
        COUNT(*) as total_docs,
        COUNT(DISTINCT CASE WHEN estado IS NOT NULL AND estado != '' AND estado != 'BR' THEN estado END) as states_with_docs,
        COUNT(DISTINCT CASE WHEN municipio IS NOT NULL AND municipio != '' THEN municipio END) as municipalities_with_docs,
        MIN(CASE WHEN data ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN data::date ELSE NULL END) as min_date,
        MAX(CASE WHEN data ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN data::date ELSE NULL END) as max_date
      FROM lexml_documents
    ")
    
    if (nrow(metrics) > 0) {
      row <- metrics[1, ]
      date_range <- "No date range"
      
      if (!is.na(row$min_date) && !is.na(row$max_date)) {
        date_range <- paste0(format(as.Date(row$min_date), "%Y"), " - ", 
                           format(as.Date(row$max_date), "%Y"))
      }
      
      return(list(
        total_docs = as.numeric(row$total_docs),
        states_with_docs = as.numeric(row$states_with_docs),
        municipalities_with_docs = as.numeric(row$municipalities_with_docs),
        date_range = date_range
      ))
    }
    
    return(list(
      total_docs = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      date_range = "No data"
    ))
    
  }, error = function(e) {
    cat("ERROR getting dashboard metrics:", e$message, "\n")
    return(list(
      total_docs = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      date_range = "No data"
    ))
  })
}

#' Force refresh database connection
force_refresh_database <- function() {
  cat("🔄 Force refreshing database connection...\n")
  
  if (!is.null(db_pool)) {
    poolClose(db_pool)
    db_pool <<- NULL
    cat("Closed existing database pool\n")
  }
  
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