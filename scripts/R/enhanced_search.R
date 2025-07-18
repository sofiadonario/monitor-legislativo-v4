# Enhanced search functionality with gender/species support
enhanced_search_documents <- function(search_text = NULL, document_types = NULL, gender_filter = NULL, species_filter = NULL, states = NULL, date_from = NULL, date_to = NULL, limit = 200) {
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Build base query
    base_query <- "
      SELECT 
        id, titulo, tipo, species, estado, 
        COALESCE(data_publicacao, created_at::date) as enacting_date, 
        url, urn
      FROM documents 
      WHERE titulo IS NOT NULL"
    
    where_conditions <- c()
    
    # Add search text filter
    if (!is.null(search_text) && nchar(search_text) > 0) {
      search_terms <- strsplit(search_text, "\\s+")[[1]]
      search_conditions <- sapply(search_terms, function(term) {
        paste0("(titulo ILIKE '%", term, "%' OR ementa ILIKE '%", term, "%')")
      })
      where_conditions <- c(where_conditions, paste0("(", paste(search_conditions, collapse = " AND "), ")"))
    }
    
    # Add gender filter
    if (!is.null(gender_filter) && gender_filter != "") {
      where_conditions <- c(where_conditions, paste0("tipo = '", gender_filter, "'"))
    }
    
    # Add species filter
    if (!is.null(species_filter) && length(species_filter) > 0) {
      species_list <- paste0("'", paste(species_filter, collapse = "','"), "'")
      where_conditions <- c(where_conditions, paste0("species IN (", species_list, ")"))
    }
    
    # Add legacy document types filter
    if (!is.null(document_types) && length(document_types) > 0) {
      types_list <- paste0("'", paste(document_types, collapse = "','"), "'")
      where_conditions <- c(where_conditions, paste0("tipo IN (", types_list, ")"))
    }
    
    # Add states filter
    if (!is.null(states) && length(states) > 0) {
      states_list <- paste0("'", paste(states, collapse = "','"), "'")
      where_conditions <- c(where_conditions, paste0("estado IN (", states_list, ")"))
    }
    
    # Add date filters
    if (!is.null(date_from)) {
      where_conditions <- c(where_conditions, paste0("COALESCE(data_publicacao, created_at::date) >= '", date_from, "'"))
    }
    
    if (!is.null(date_to)) {
      where_conditions <- c(where_conditions, paste0("COALESCE(data_publicacao, created_at::date) <= '", date_to, "'"))
    }
    
    # Combine all conditions
    if (length(where_conditions) > 0) {
      full_query <- paste(base_query, "AND", paste(where_conditions, collapse = " AND "))
    } else {
      full_query <- base_query
    }
    
    # Add ordering and limit
    full_query <- paste(full_query, "ORDER BY COALESCE(data_publicacao, created_at::date) DESC LIMIT", limit)
    
    cat("Enhanced search query:", full_query, "\n")
    result <- dbGetQuery(conn, full_query)
    
    return(result)
    
  }, error = function(e) {
    cat("Error in enhanced search:", e$message, "\n")
    return(data.frame())
  })
}