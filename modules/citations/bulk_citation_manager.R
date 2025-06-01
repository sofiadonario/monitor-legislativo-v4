# BULK CITATION MANAGEMENT SYSTEM - CIT-004
# =========================================
# Advanced citation management for multiple Brazilian legislative documents
# Supports citation collections, projects, and batch operations
# 
# Features:
# - Select multiple documents for citation
# - Citation collections/projects management
# - Batch export in chosen formats
# - Maintain citation ordering
# - Generate bibliography sections
# - Memory-efficient processing for large document sets
# - Integration with existing database connection

cat("Loading Bulk Citation Management System...\n")

# Global citation collections storage
citation_collections <- list()
active_collection <- NULL

# CITATION COLLECTION MANAGEMENT
# ==============================

#' Create New Citation Collection
#' @param collection_name Name for the citation collection
#' @param description Optional description
#' @param format Default citation format
#' @param language Default language
#' @return Collection ID
create_citation_collection <- function(collection_name, description = "", format = "abnt", language = "pt") {
  if (is.null(collection_name) || collection_name == "") {
    stop("Collection name cannot be empty")
  }
  
  # Generate unique collection ID
  collection_id <- paste0("collection_", 
                         format(Sys.time(), "%Y%m%d_%H%M%S"), "_",
                         sample(1000:9999, 1))
  
  # Create collection structure
  new_collection <- list(
    id = collection_id,
    name = collection_name,
    description = description,
    created_date = Sys.time(),
    modified_date = Sys.time(),
    format = format,
    language = language,
    documents = list(),
    document_count = 0,
    metadata = list(),
    ordering = c(),
    tags = c()
  )
  
  # Store collection
  citation_collections[[collection_id]] <<- new_collection
  
  cat("✅ Created citation collection:", collection_name, "(ID:", collection_id, ")\n")
  
  return(collection_id)
}

#' Add Documents to Citation Collection
#' @param collection_id Collection identifier
#' @param document_data Document data (single document or data frame)
#' @param title_column Column name for document title
#' @param parse_metadata Whether to parse metadata immediately
#' @return Number of documents added
add_documents_to_collection <- function(collection_id, document_data, 
                                       title_column = "title", 
                                       parse_metadata = TRUE) {
  
  if (!collection_id %in% names(citation_collections)) {
    stop(paste("Collection not found:", collection_id))
  }
  
  # Load parser if needed
  if (parse_metadata && !exists("parse_brazilian_legislative_metadata")) {
    if (file.exists("modules/citations/brazilian_legislative_parser.R")) {
      source("modules/citations/brazilian_legislative_parser.R")
    }
  }
  
  collection <- citation_collections[[collection_id]]
  documents_added <- 0
  
  # Handle single document or data frame
  if (is.data.frame(document_data)) {
    for (i in 1:nrow(document_data)) {
      doc_row <- document_data[i, , drop = FALSE]
      doc_id <- add_single_document_to_collection(collection, doc_row, title_column, parse_metadata)
      if (!is.null(doc_id)) {
        documents_added <- documents_added + 1
      }
    }
  } else {
    doc_id <- add_single_document_to_collection(collection, document_data, title_column, parse_metadata)
    if (!is.null(doc_id)) {
      documents_added <- 1
    }
  }
  
  # Update collection
  collection$document_count <- length(collection$documents)
  collection$modified_date <- Sys.time()
  citation_collections[[collection_id]] <<- collection
  
  cat("✅ Added", documents_added, "document(s) to collection:", collection$name, "\n")
  
  return(documents_added)
}

#' Add Single Document to Collection (internal)
#' @param collection Collection object
#' @param doc_data Single document data
#' @param title_column Title column name
#' @param parse_metadata Whether to parse metadata
#' @return Document ID or NULL if failed
add_single_document_to_collection <- function(collection, doc_data, title_column, parse_metadata) {
  
  # Generate document ID
  doc_id <- paste0("doc_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", 
                   sample(100:999, 1))
  
  # Extract basic info
  title <- get_column_value_safe(doc_data, title_column)
  if (title == "") {
    cat("⚠️ Skipping document with empty title\n")
    return(NULL)
  }
  
  # Create document entry
  document_entry <- list(
    id = doc_id,
    title = title,
    raw_data = doc_data,
    parsed_metadata = NULL,
    added_date = Sys.time(),
    tags = c(),
    notes = "",
    position = length(collection$documents) + 1
  )
  
  # Parse metadata if requested
  if (parse_metadata && exists("parse_brazilian_legislative_metadata")) {
    tryCatch({
      parsed_result <- parse_brazilian_legislative_metadata(doc_data, title_column)
      if (is.list(parsed_result) && length(parsed_result) > 0) {
        document_entry$parsed_metadata <- parsed_result[[1]]
      }
    }, error = function(e) {
      cat("⚠️ Failed to parse metadata for:", title, "-", e$message, "\n")
    })
  }
  
  # Add to collection
  collection$documents[[doc_id]] <- document_entry
  collection$ordering <- c(collection$ordering, doc_id)
  
  return(doc_id)
}

#' Remove Documents from Collection
#' @param collection_id Collection identifier
#' @param document_ids Vector of document IDs to remove
#' @return Number of documents removed
remove_documents_from_collection <- function(collection_id, document_ids) {
  if (!collection_id %in% names(citation_collections)) {
    stop(paste("Collection not found:", collection_id))
  }
  
  collection <- citation_collections[[collection_id]]
  documents_removed <- 0
  
  for (doc_id in document_ids) {
    if (doc_id %in% names(collection$documents)) {
      collection$documents[[doc_id]] <- NULL
      collection$ordering <- collection$ordering[collection$ordering != doc_id]
      documents_removed <- documents_removed + 1
    }
  }
  
  # Update collection
  collection$document_count <- length(collection$documents)
  collection$modified_date <- Sys.time()
  citation_collections[[collection_id]] <<- collection
  
  cat("✅ Removed", documents_removed, "document(s) from collection\n")
  
  return(documents_removed)
}

#' Reorder Documents in Collection
#' @param collection_id Collection identifier
#' @param new_order Vector of document IDs in desired order
#' @return TRUE if successful
reorder_collection_documents <- function(collection_id, new_order) {
  if (!collection_id %in% names(citation_collections)) {
    stop(paste("Collection not found:", collection_id))
  }
  
  collection <- citation_collections[[collection_id]]
  
  # Validate that all documents in new_order exist
  valid_docs <- new_order[new_order %in% names(collection$documents)]
  
  if (length(valid_docs) != length(collection$documents)) {
    cat("⚠️ Some documents in new order are invalid. Using valid subset.\n")
  }
  
  # Update ordering
  collection$ordering <- valid_docs
  collection$modified_date <- Sys.time()
  citation_collections[[collection_id]] <<- collection
  
  cat("✅ Reordered", length(valid_docs), "documents in collection\n")
  
  return(TRUE)
}

# BATCH CITATION GENERATION
# =========================

#' Generate Citations for Entire Collection
#' @param collection_id Collection identifier
#' @param format Citation format ("abnt", "apa", "vancouver", "bluebook")
#' @param language Language for citations
#' @param include_bibliography Whether to include bibliography header
#' @return Formatted citations string
generate_collection_citations <- function(collection_id, format = NULL, language = NULL, include_bibliography = TRUE) {
  if (!collection_id %in% names(citation_collections)) {
    stop(paste("Collection not found:", collection_id))
  }
  
  collection <- citation_collections[[collection_id]]
  
  # Use collection defaults if not specified
  format <- format %||% collection$format
  language <- language %||% collection$language
  
  # Load citation templates if needed
  if (!exists("format_abnt_citation")) {
    if (file.exists("modules/citations/citation_templates.R")) {
      source("modules/citations/citation_templates.R")
    } else {
      stop("Citation templates not available")
    }
  }
  
  if (collection$document_count == 0) {
    return("No documents in collection")
  }
  
  citations <- c()
  
  # Add bibliography header if requested
  if (include_bibliography) {
    if (format == "abnt") {
      if (language == "pt") {
        citations <- c(citations, "REFERÊNCIAS", "")
      } else {
        citations <- c(citations, "REFERENCES", "")
      }
    } else {
      header <- paste("CITATIONS -", toupper(format))
      citations <- c(citations, header, "")
    }
  }
  
  # Generate citations in order
  citation_function <- get_citation_function(format)
  
  for (doc_id in collection$ordering) {
    if (doc_id %in% names(collection$documents)) {
      document <- collection$documents[[doc_id]]
      
      if (!is.null(document$parsed_metadata)) {
        # Use parsed metadata
        if (format == "vancouver") {
          citation <- citation_function(document$parsed_metadata, which(collection$ordering == doc_id))
        } else {
          citation <- citation_function(document$parsed_metadata, language)
        }
      } else {
        # Fallback: basic citation from raw data
        citation <- generate_fallback_citation(document, format)
      }
      
      citations <- c(citations, citation, "")
    }
  }
  
  return(paste(citations, collapse = "\n"))
}

#' Batch Export Collection in Multiple Formats
#' @param collection_id Collection identifier
#' @param output_dir Output directory
#' @param formats Vector of formats to export
#' @param filename_prefix Filename prefix
#' @return Export results
batch_export_collection <- function(collection_id, 
                                   output_dir = "exports",
                                   formats = c("abnt_plain", "bibtex", "ris"),
                                   filename_prefix = NULL) {
  
  if (!collection_id %in% names(citation_collections)) {
    stop(paste("Collection not found:", collection_id))
  }
  
  collection <- citation_collections[[collection_id]]
  
  # Generate filename prefix if not provided
  if (is.null(filename_prefix)) {
    safe_name <- gsub("[^a-zA-Z0-9_-]", "_", collection$name)
    filename_prefix <- paste0(safe_name, "_", format(Sys.Date(), "%Y%m%d"))
  }
  
  # Load export system if needed
  if (!exists("bulk_export_citations")) {
    if (file.exists("modules/citations/citation_export.R")) {
      source("modules/citations/citation_export.R")
    } else {
      stop("Citation export system not available")
    }
  }
  
  # Extract parsed metadata from collection
  metadata_list <- list()
  for (doc_id in collection$ordering) {
    if (doc_id %in% names(collection$documents)) {
      document <- collection$documents[[doc_id]]
      if (!is.null(document$parsed_metadata)) {
        metadata_list <- append(metadata_list, list(document$parsed_metadata))
      }
    }
  }
  
  if (length(metadata_list) == 0) {
    cat("⚠️ No parsed metadata available for export\n")
    return(NULL)
  }
  
  # Perform batch export
  export_results <- bulk_export_citations(metadata_list, output_dir, filename_prefix, formats)
  
  cat("📦 Batch export completed for collection:", collection$name, "\n")
  
  return(export_results)
}

# COLLECTION SEARCH AND FILTERING
# ===============================

#' Search Documents within Collection
#' @param collection_id Collection identifier
#' @param search_term Search term
#' @param search_fields Fields to search in
#' @return Vector of matching document IDs
search_collection_documents <- function(collection_id, search_term, search_fields = c("title", "notes")) {
  if (!collection_id %in% names(citation_collections)) {
    stop(paste("Collection not found:", collection_id))
  }
  
  collection <- citation_collections[[collection_id]]
  matching_docs <- c()
  
  if (search_term == "" || is.null(search_term)) {
    return(names(collection$documents))
  }
  
  search_pattern <- paste0(".*", search_term, ".*")
  
  for (doc_id in names(collection$documents)) {
    document <- collection$documents[[doc_id]]
    found_match <- FALSE
    
    # Search in specified fields
    for (field in search_fields) {
      field_value <- ""
      
      if (field == "title" && !is.null(document$title)) {
        field_value <- document$title
      } else if (field == "notes" && !is.null(document$notes)) {
        field_value <- document$notes
      } else if (field == "tags" && length(document$tags) > 0) {
        field_value <- paste(document$tags, collapse = " ")
      }
      
      if (grepl(search_pattern, field_value, ignore.case = TRUE)) {
        found_match <- TRUE
        break
      }
    }
    
    if (found_match) {
      matching_docs <- c(matching_docs, doc_id)
    }
  }
  
  return(matching_docs)
}

#' Filter Collection by Tags
#' @param collection_id Collection identifier
#' @param required_tags Vector of required tags
#' @return Vector of matching document IDs
filter_collection_by_tags <- function(collection_id, required_tags) {
  if (!collection_id %in% names(citation_collections)) {
    stop(paste("Collection not found:", collection_id))
  }
  
  collection <- citation_collections[[collection_id]]
  matching_docs <- c()
  
  for (doc_id in names(collection$documents)) {
    document <- collection$documents[[doc_id]]
    
    if (length(document$tags) > 0) {
      # Check if all required tags are present
      has_all_tags <- all(required_tags %in% document$tags)
      if (has_all_tags) {
        matching_docs <- c(matching_docs, doc_id)
      }
    }
  }
  
  return(matching_docs)
}

# COLLECTION UTILITIES
# ===================

#' Get Collection Information
#' @param collection_id Collection identifier (optional - returns all if NULL)
#' @return Collection information
get_collection_info <- function(collection_id = NULL) {
  if (is.null(collection_id)) {
    # Return summary of all collections
    collection_summary <- list()
    
    for (cid in names(citation_collections)) {
      collection <- citation_collections[[cid]]
      collection_summary[[cid]] <- list(
        id = collection$id,
        name = collection$name,
        description = collection$description,
        document_count = collection$document_count,
        created_date = collection$created_date,
        modified_date = collection$modified_date,
        format = collection$format,
        language = collection$language
      )
    }
    
    return(collection_summary)
  }
  
  if (!collection_id %in% names(citation_collections)) {
    return(NULL)
  }
  
  return(citation_collections[[collection_id]])
}

#' Delete Citation Collection
#' @param collection_id Collection identifier
#' @return TRUE if successful
delete_collection <- function(collection_id) {
  if (!collection_id %in% names(citation_collections)) {
    cat("⚠️ Collection not found:", collection_id, "\n")
    return(FALSE)
  }
  
  collection_name <- citation_collections[[collection_id]]$name
  citation_collections[[collection_id]] <<- NULL
  
  cat("✅ Deleted collection:", collection_name, "\n")
  
  return(TRUE)
}

#' Add Tags to Document in Collection
#' @param collection_id Collection identifier
#' @param document_id Document identifier
#' @param tags Vector of tags to add
#' @return TRUE if successful
add_document_tags <- function(collection_id, document_id, tags) {
  if (!collection_id %in% names(citation_collections)) {
    return(FALSE)
  }
  
  collection <- citation_collections[[collection_id]]
  
  if (!document_id %in% names(collection$documents)) {
    return(FALSE)
  }
  
  document <- collection$documents[[document_id]]
  document$tags <- unique(c(document$tags, tags))
  
  collection$documents[[document_id]] <- document
  collection$modified_date <- Sys.time()
  citation_collections[[collection_id]] <<- collection
  
  return(TRUE)
}

#' Add Notes to Document in Collection
#' @param collection_id Collection identifier
#' @param document_id Document identifier
#' @param notes Notes text
#' @return TRUE if successful
add_document_notes <- function(collection_id, document_id, notes) {
  if (!collection_id %in% names(citation_collections)) {
    return(FALSE)
  }
  
  collection <- citation_collections[[collection_id]]
  
  if (!document_id %in% names(collection$documents)) {
    return(FALSE)
  }
  
  document <- collection$documents[[document_id]]
  document$notes <- notes
  
  collection$documents[[document_id]] <- document
  collection$modified_date <- Sys.time()
  citation_collections[[collection_id]] <<- collection
  
  return(TRUE)
}

# HELPER FUNCTIONS
# ===============

#' Get Citation Function by Format
#' @param format Citation format
#' @return Citation function
get_citation_function <- function(format) {
  function_name <- paste0("format_", format, "_citation")
  
  if (exists(function_name)) {
    return(get(function_name))
  } else {
    return(function(metadata, ...) paste("Unsupported format:", format))
  }
}

#' Generate Fallback Citation
#' @param document Document object
#' @param format Citation format
#' @return Basic citation string
generate_fallback_citation <- function(document, format) {
  if (format == "abnt") {
    return(paste0("AUTOR DESCONHECIDO. ", document$title, ". [Local desconhecido]: [Editor desconhecido], [data desconhecida]."))
  } else {
    return(paste0("Unknown Author. ", document$title, ". Unknown Publisher."))
  }
}

#' Safe Column Value Extraction
#' @param data Data object
#' @param column_name Column name
#' @return Column value or empty string
get_column_value_safe <- function(data, column_name) {
  if (is.data.frame(data)) {
    if (column_name %in% names(data)) {
      value <- data[[column_name]][1]
      return(if (is.na(value)) "" else as.character(value))
    }
  } else if (is.list(data)) {
    if (column_name %in% names(data)) {
      value <- data[[column_name]]
      return(if (is.na(value)) "" else as.character(value))
    }
  }
  return("")
}

`%||%` <- function(a, b) if (is.null(a)) b else a

#' Test Bulk Citation Manager
#' @return Test results
test_bulk_citation_manager <- function() {
  cat("Testing Bulk Citation Management System...\n")
  
  # Create test collection
  collection_id <- create_citation_collection("Test Collection", "Testing bulk citation management")
  
  # Test documents
  test_docs <- data.frame(
    title = c(
      "Lei Federal nº 14.133/2021 - Nova Lei de Licitações",
      "Decreto nº 10.881/2021 - Governo Digital",
      "Resolução ANTT nº 5.232/2020 - RNTRC"
    ),
    state = c("DF", "DF", "DF"),
    date = c("2021-04-01", "2021-06-15", "2020-12-10"),
    url = c("", "", ""),
    urn = c("", "", ""),
    stringsAsFactors = FALSE
  )
  
  # Add documents to collection
  added_count <- add_documents_to_collection(collection_id, test_docs, parse_metadata = FALSE)
  
  # Test search
  search_results <- search_collection_documents(collection_id, "Lei")
  
  # Test citation generation
  citations <- generate_collection_citations(collection_id, "abnt", "pt")
  
  # Get collection info
  info <- get_collection_info(collection_id)
  
  cat("\n--- TEST RESULTS ---\n")
  cat("Collection ID:", collection_id, "\n")
  cat("Documents added:", added_count, "\n")
  cat("Search results:", length(search_results), "\n")
  cat("Citations generated:", nchar(citations) > 0, "\n")
  cat("Collection info available:", !is.null(info), "\n")
  
  # Clean up
  delete_collection(collection_id)
  
  return(list(
    collection_created = !is.null(collection_id),
    documents_added = added_count,
    search_functional = length(search_results) > 0,
    citations_generated = nchar(citations) > 0
  ))
}

cat("✅ Bulk Citation Management System loaded successfully\n")
cat("   📚 Citation collections: ENABLED\n")
cat("   📝 Batch citation generation: ENABLED\n")
cat("   📦 Multi-format export: ENABLED\n")
cat("   🔍 Collection search: ENABLED\n")
cat("   🏷️ Document tagging: ENABLED\n")
cat("   📋 Citation ordering: ENABLED\n")

# Export main functions
BULK_CITATION_FUNCTIONS <- list(
  create_citation_collection = create_citation_collection,
  add_documents_to_collection = add_documents_to_collection,
  remove_documents_from_collection = remove_documents_from_collection,
  reorder_collection_documents = reorder_collection_documents,
  generate_collection_citations = generate_collection_citations,
  batch_export_collection = batch_export_collection,
  search_collection_documents = search_collection_documents,
  filter_collection_by_tags = filter_collection_by_tags,
  get_collection_info = get_collection_info,
  delete_collection = delete_collection,
  add_document_tags = add_document_tags,
  add_document_notes = add_document_notes,
  test_bulk_citation_manager = test_bulk_citation_manager
)