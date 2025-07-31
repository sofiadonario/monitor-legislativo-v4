# Additional server logic for gender/species functionality
# This code should be added to the server function in app.R

# Update species choices based on gender selection
observeEvent(input$genderFilter, {
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      
      # Get species choices based on selected gender
      if (input$genderFilter == "") {
        # All species from both genders
        species_query <- "SELECT DISTINCT species FROM documents WHERE species IS NOT NULL AND species != '' ORDER BY species"
      } else {
        # Species from selected gender only
        species_query <- paste0("SELECT DISTINCT species FROM documents WHERE tipo = '", input$genderFilter, "' AND species IS NOT NULL AND species != '' ORDER BY species")
      }
      
      species_choices <- dbGetQuery(conn, species_query)$species
      updateSelectizeInput(session, "speciesFilter", choices = species_choices)
      
    }, error = function(e) {
      cat("Error updating species choices:", e$message, "\n")
    })
  }
})

# Initialize species filter choices on startup
observe({
  if (database_connected && !is.null(db_pool)) {
    tryCatch({
      conn <- poolCheckout(db_pool)
      on.exit(poolReturn(conn))
      
      # Get all available species
      species_choices <- dbGetQuery(conn, "SELECT DISTINCT species FROM documents WHERE species IS NOT NULL AND species != '' ORDER BY species")$species
      updateSelectizeInput(session, "speciesFilter", choices = species_choices)
      
    }, error = function(e) {
      cat("Error initializing species choices:", e$message, "\n")
    })
  }
})

# Enhanced search functionality that includes gender and species filters
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

# Update the search button event handler to use enhanced search
observeEvent(input$searchBtn, {
  if (database_connected) {
    withProgress(message = 'Searching documents...', value = 0, {
      incProgress(0.3)
      
      # Get filter values including new gender/species filters
      search_text <- input$searchText
      doc_types <- input$documentTypes
      gender_filter <- input$genderFilter
      species_filter <- input$speciesFilter
      states_filter <- input$states
      date_from <- input$dateFrom
      date_to <- input$dateTo
      
      incProgress(0.7)
      
      # Perform enhanced search with gender/species support
      values$search_results <- enhanced_search_documents(
        search_text = search_text,
        document_types = doc_types,
        gender_filter = gender_filter,
        species_filter = species_filter,
        states = states_filter,
        date_from = date_from,
        date_to = date_to,
        limit = 200
      )
      
      incProgress(1)
    })
  }
})

# Update clear filters to include new filters
observeEvent(input$clearBtn, {
  updateTextInput(session, "searchText", value = "")
  updateSelectizeInput(session, "genderFilter", selected = "")
  updateSelectizeInput(session, "speciesFilter", selected = NULL)
  updateSelectizeInput(session, "documentTypes", selected = NULL)
  updateSelectizeInput(session, "states", selected = NULL)
  updateDateInput(session, "dateFrom", value = NULL)
  updateDateInput(session, "dateTo", value = NULL)
  values$search_results <- NULL
})

# Update the search results table to include species column
output$searchResults <- DT::renderDataTable({
  if (database_connected) {
    data <- values$search_results
    
    if (is.null(data)) {
      empty_data <- data.frame(
        Message = "Enter search terms and click Search",
        stringsAsFactors = FALSE
      )
      return(DT::datatable(empty_data, options = list(searching = FALSE)))
    }
    
    if (nrow(data) == 0) {
      empty_data <- data.frame(
        Message = paste("No results found for your search criteria"),
        stringsAsFactors = FALSE
      )
      return(DT::datatable(empty_data, options = list(searching = FALSE)))
    }
    
    # Format search results with species column
    display_data <- data %>%
      select(titulo, tipo, species, estado, enacting_date, urn) %>%
      rename(
        "Title" = titulo,
        "Gender" = tipo,
        "Species" = species,
        "State" = estado, 
        "Enacting Date" = enacting_date,
        "URN" = urn
      )
    
    # Highlight search terms in titles if search text was provided
    if (!is.null(input$searchText) && nchar(input$searchText) > 0) {
      search_terms <- strsplit(input$searchText, "\\s+")[[1]]
      display_data$Title <- sapply(display_data$Title, function(title) {
        highlight_search_terms(title, search_terms)
      })
    }
    
    DT::datatable(
      display_data,
      options = list(
        pageLength = 25,
        scrollX = TRUE,
        columnDefs = list(
          list(width = "35%", targets = 0),  # Title column
          list(width = "12%", targets = 1:2), # Gender, Species
          list(width = "12%", targets = 3:4), # State, Date
          list(width = "29%", targets = 5)   # URN column
        )
      ),
      rownames = FALSE,
      escape = FALSE  # Allow HTML in cells for highlighting
    )
  }
})

# Update search summary to include gender/species information
output$searchSummary <- renderUI({
  if (!is.null(values$search_results)) {
    result_count <- nrow(values$search_results)
    
    # Build filter summary including gender/species
    filter_parts <- c()
    if (!is.null(input$searchText) && nchar(input$searchText) > 0) {
      filter_parts <- c(filter_parts, paste("Text:", input$searchText))
    }
    if (!is.null(input$genderFilter) && input$genderFilter != "") {
      filter_parts <- c(filter_parts, paste("Gender:", input$genderFilter))
    }
    if (!is.null(input$speciesFilter) && length(input$speciesFilter) > 0) {
      filter_parts <- c(filter_parts, paste("Species:", paste(input$speciesFilter, collapse = ", ")))
    }
    if (!is.null(input$documentTypes) && length(input$documentTypes) > 0) {
      filter_parts <- c(filter_parts, paste("Legacy Types:", paste(input$documentTypes, collapse = ", ")))
    }
    if (!is.null(input$states) && length(input$states) > 0) {
      filter_parts <- c(filter_parts, paste("States:", paste(input$states, collapse = ", ")))
    }
    if (!is.null(input$dateFrom) || !is.null(input$dateTo)) {
      date_part <- "Date range:"
      if (!is.null(input$dateFrom)) date_part <- paste(date_part, "from", input$dateFrom)
      if (!is.null(input$dateTo)) date_part <- paste(date_part, "to", input$dateTo)
      filter_parts <- c(filter_parts, date_part)
    }
    
    if (result_count > 0) {
      # Show breakdown by gender and species if applicable
      gender_breakdown <- ""
      if (nrow(values$search_results) > 0 && "tipo" %in% names(values$search_results)) {
        gender_counts <- table(values$search_results$tipo)
        if (length(gender_counts) > 0) {
          gender_breakdown <- paste0(
            "<br><strong>Gender breakdown:</strong> ",
            paste(names(gender_counts), ": ", gender_counts, collapse = ", ")
          )
        }
        
        if ("species" %in% names(values$search_results)) {
          species_counts <- table(values$search_results$species)
          if (length(species_counts) > 1) {
            top_species <- head(sort(species_counts, decreasing = TRUE), 3)
            gender_breakdown <- paste0(
              gender_breakdown,
              "<br><strong>Top species:</strong> ",
              paste(names(top_species), ": ", top_species, collapse = ", ")
            )
          }
        }
      }
      
      div(
        class = "alert alert-info",
        icon("info-circle"),
        strong(paste("Found", result_count, "documents")),
        if (result_count == 200) " (showing first 200 results)" else "",
        HTML(gender_breakdown),
        if (!is.null(input$searchText) && nchar(input$searchText) > 0) {
          div(
            br(),
            icon("star"),
            em("Results ranked by relevance (title matches first, then content)")
          )
        },
        if (length(filter_parts) > 0) {
          div(
            br(),
            strong("Applied filters: "),
            paste(filter_parts, collapse = " | ")
          )
        }
      )
    } else {
      div(
        class = "alert alert-warning",
        icon("exclamation-triangle"),
        "No documents found matching your search criteria.",
        if (length(filter_parts) > 0) {
          div(
            br(),
            strong("Applied filters: "),
            paste(filter_parts, collapse = " | "),
            br(),
            "Try adjusting your filters."
          )
        } else {
          div(
            br(),
            "Try adding some search criteria."
          )
        }
      )
    }
  }
})