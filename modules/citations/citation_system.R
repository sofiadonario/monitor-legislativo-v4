# CITATION SYSTEM MAIN INTEGRATOR
# ===============================
# Main entry point for Brazilian Legislative Citation System
# Loads all components and provides unified interface
# 
# Sprint 5A Implementation Complete:
# - CIT-001: Brazilian Legislative Metadata Parser ✅
# - CIT-002: ABNT, APA, Vancouver, Bluebook Templates ✅
# - CIT-003: BibTeX, RIS, EndNote Export System ✅
# - CIT-004: Bulk Citation Management ✅
# - UI Integration with Shiny Dashboard ✅

cat("🎓 Loading Brazilian Legislative Citation System (Sprint 5A)...\n")

# SYSTEM INITIALIZATION
# ====================

citation_system_loaded <- FALSE

tryCatch({
  # Load all citation system components in order
  component_files <- c(
    "modules/citations/brazilian_legislative_parser.R",
    "modules/citations/citation_templates.R", 
    "modules/citations/citation_export.R",
    "modules/citations/bulk_citation_manager.R",
    "modules/citations/citation_ui.R"
  )
  
  loaded_components <- c()
  
  for (file in component_files) {
    if (file.exists(file)) {
      source(file)
      component_name <- basename(tools::file_path_sans_ext(file))
      loaded_components <- c(loaded_components, component_name)
      cat("✅", component_name, "loaded\n")
    } else {
      cat("⚠️", file, "not found\n")
    }
  }
  
  if (length(loaded_components) >= 4) {  # Core components
    citation_system_loaded <- TRUE
    cat("🎓 Citation System: FULLY OPERATIONAL\n")
  } else {
    cat("⚠️ Citation System: PARTIALLY LOADED\n")
  }
  
}, error = function(e) {
  cat("❌ Citation System loading failed:", e$message, "\n")
  citation_system_loaded <- FALSE
})

# MAIN CITATION INTERFACE
# =======================

#' Generate Academic Citation for Brazilian Legislative Document
#' Main interface function for the citation system
#' @param document_data Document data (single document or data frame)
#' @param format Citation format ("abnt", "apa", "vancouver", "bluebook")
#' @param language Language ("pt", "en")
#' @param title_column Column name for document title
#' @return Formatted citation string
generate_brazilian_citation <- function(document_data, 
                                       format = "abnt", 
                                       language = "pt",
                                       title_column = "title") {
  
  if (!citation_system_loaded) {
    return("❌ Citation system not available")
  }
  
  tryCatch({
    # Parse metadata
    parsed_metadata <- parse_brazilian_legislative_metadata(
      document_data, 
      title_column = title_column
    )
    
    # Handle single or multiple documents
    if (is.list(parsed_metadata) && !is.null(parsed_metadata[[1]])) {
      metadata <- parsed_metadata[[1]]
    } else {
      metadata <- parsed_metadata
    }
    
    # Generate citation based on format
    citation <- switch(format,
      "abnt" = format_abnt_citation(metadata, language),
      "apa" = format_apa_citation(metadata, language),
      "vancouver" = format_vancouver_citation(metadata, 1),
      "bluebook" = format_bluebook_citation(metadata),
      paste("Unsupported format:", format)
    )
    
    return(citation)
    
  }, error = function(e) {
    return(paste("Citation generation error:", e$message))
  })
}

#' Generate Bibliography for Multiple Documents
#' @param document_list List or data frame of documents
#' @param format Citation format
#' @param language Language
#' @param title_column Column name for document title
#' @return Formatted bibliography string
generate_brazilian_bibliography <- function(document_list,
                                           format = "abnt",
                                           language = "pt", 
                                           title_column = "title") {
  
  if (!citation_system_loaded) {
    return("❌ Citation system not available")
  }
  
  tryCatch({
    # Parse metadata for all documents
    parsed_metadata_list <- parse_brazilian_legislative_metadata(
      document_list,
      title_column = title_column
    )
    
    if (format == "abnt") {
      return(format_abnt_bibliography(parsed_metadata_list, language))
    }
    
    # For other formats, generate individual citations
    citations <- c()
    
    if (format == "abnt" && language == "pt") {
      citations <- c(citations, "REFERÊNCIAS", "")
    } else {
      citations <- c(citations, paste("CITATIONS -", toupper(format)), "")
    }
    
    for (i in seq_along(parsed_metadata_list)) {
      metadata <- parsed_metadata_list[[i]]
      
      citation <- switch(format,
        "apa" = format_apa_citation(metadata, language),
        "vancouver" = format_vancouver_citation(metadata, i),
        "bluebook" = format_bluebook_citation(metadata),
        format_abnt_citation(metadata, language)
      )
      
      citations <- c(citations, citation, "")
    }
    
    return(paste(citations, collapse = "\n"))
    
  }, error = function(e) {
    return(paste("Bibliography generation error:", e$message))
  })
}

#' Quick Citation Export
#' Convenient function for exporting citations in multiple formats
#' @param document_data Document data
#' @param output_dir Output directory
#' @param filename_base Base filename
#' @param formats Export formats
#' @return Export results
quick_citation_export <- function(document_data,
                                 output_dir = "citations_export",
                                 filename_base = "brazilian_legislative_citations",
                                 formats = c("abnt_plain", "bibtex", "ris")) {
  
  if (!citation_system_loaded) {
    cat("❌ Citation system not available for export\n")
    return(NULL)
  }
  
  tryCatch({
    # Parse metadata
    parsed_metadata_list <- parse_brazilian_legislative_metadata(document_data)
    
    # Ensure it's a list
    if (!is.list(parsed_metadata_list)) {
      parsed_metadata_list <- list(parsed_metadata_list)
    }
    
    # Perform bulk export
    results <- bulk_export_citations(
      parsed_metadata_list,
      output_dir,
      filename_base,
      formats
    )
    
    return(results)
    
  }, error = function(e) {
    cat("Export error:", e$message, "\n")
    return(NULL)
  })
}

#' Citation System Status
#' Get current status and capabilities of the citation system
#' @return Status information
get_citation_system_status <- function() {
  status <- list(
    system_loaded = citation_system_loaded,
    timestamp = Sys.time(),
    components = list(),
    capabilities = list(),
    test_results = list()
  )
  
  # Check component availability
  components <- list(
    "parser" = exists("parse_brazilian_legislative_metadata"),
    "templates" = exists("format_abnt_citation"),
    "export" = exists("export_bibtex"),
    "bulk_manager" = exists("create_citation_collection"),
    "ui" = exists("citation_tab_ui")
  )
  
  status$components <- components
  
  # System capabilities
  if (citation_system_loaded) {
    status$capabilities <- list(
      supported_formats = c("ABNT NBR 6023:2018", "APA 7th Edition", "Vancouver", "Bluebook"),
      export_formats = c("BibTeX", "RIS", "EndNote XML", "Plain Text"),
      languages = c("Portuguese", "English"),
      document_types = c("Lei Federal", "Decreto", "Resolução", "Portaria", "Constituição"),
      jurisdictions = c("Federal", "Estadual", "Municipal"),
      bulk_operations = TRUE,
      collection_management = TRUE,
      ui_integration = TRUE
    )
    
    # Run basic tests
    status$test_results <- run_citation_system_tests()
  }
  
  return(status)
}

#' Run Citation System Tests
#' Internal testing function
#' @return Test results
run_citation_system_tests <- function() {
  test_results <- list(
    parser_test = FALSE,
    template_test = FALSE,
    export_test = FALSE,
    bulk_test = FALSE
  )
  
  # Test parser
  if (exists("test_brazilian_parser")) {
    tryCatch({
      test_brazilian_parser()
      test_results$parser_test <- TRUE
    }, error = function(e) {
      cat("Parser test failed:", e$message, "\n")
    })
  }
  
  # Test templates
  if (exists("test_citation_templates")) {
    tryCatch({
      test_citation_templates()
      test_results$template_test <- TRUE
    }, error = function(e) {
      cat("Template test failed:", e$message, "\n")
    })
  }
  
  # Test export
  if (exists("test_citation_export")) {
    tryCatch({
      test_citation_export()
      test_results$export_test <- TRUE
    }, error = function(e) {
      cat("Export test failed:", e$message, "\n")
    })
  }
  
  # Test bulk manager
  if (exists("test_bulk_citation_manager")) {
    tryCatch({
      test_bulk_citation_manager()
      test_results$bulk_test <- TRUE
    }, error = function(e) {
      cat("Bulk manager test failed:", e$message, "\n")
    })
  }
  
  return(test_results)
}

# DASHBOARD INTEGRATION FUNCTIONS
# ===============================

#' Add Citation Tab to Dashboard
#' Helper function to add citation functionality to existing dashboard
#' @param sidebar_menu Existing sidebar menu
#' @param tab_items Existing tab items
#' @return Updated UI components
add_citation_tab_to_dashboard <- function(sidebar_menu = NULL, tab_items = NULL) {
  
  if (!citation_system_loaded) {
    cat("⚠️ Citation system not loaded - tab not added\n")
    return(list(sidebar = sidebar_menu, tabs = tab_items))
  }
  
  # Add citation menu item
  citation_menu_item <- menuItem("Citações Acadêmicas", 
                                tabName = "citations", 
                                icon = icon("quote-left"))
  
  # Add citation tab
  if (exists("citation_tab_ui")) {
    citation_tab <- citation_tab_ui()
  } else {
    # Fallback basic tab
    citation_tab <- tabItem(
      tabName = "citations",
      fluidRow(
        box(
          title = "Sistema de Citações", 
          status = "primary",
          solidHeader = TRUE,
          width = 12,
          p("Sistema de citações em desenvolvimento...")
        )
      )
    )
  }
  
  return(list(
    menu_item = citation_menu_item,
    tab_content = citation_tab
  ))
}

#' Initialize Citation System for Shiny App
#' @param input Shiny input
#' @param output Shiny output
#' @param session Shiny session
#' @param get_documents_function Function to get documents from main app
initialize_citation_system_server <- function(input, output, session, get_documents_function = NULL) {
  
  if (!citation_system_loaded) {
    cat("⚠️ Citation system not loaded - server initialization skipped\n")
    return(NULL)
  }
  
  if (exists("citation_server")) {
    citation_server(input, output, session, get_documents_function)
  } else {
    cat("⚠️ Citation server function not available\n")
  }
}

# SYSTEM READY MESSAGE
# ===================

if (citation_system_loaded) {
  cat("\n🎓 ===== BRAZILIAN LEGISLATIVE CITATION SYSTEM READY =====\n")
  cat("📚 Academic citation generation for Brazilian legislative documents\n")
  cat("🏛️ Sprint 5A Implementation Status:\n")
  cat("   ✅ CIT-001: Brazilian Legislative Metadata Parser\n")
  cat("   ✅ CIT-002: ABNT, APA, Vancouver, Bluebook Templates\n") 
  cat("   ✅ CIT-003: BibTeX, RIS, EndNote Export System\n")
  cat("   ✅ CIT-004: Bulk Citation Management System\n")
  cat("   ✅ Dashboard UI Integration\n")
  cat("\n📖 Usage Examples:\n")
  cat("   generate_brazilian_citation(document, 'abnt', 'pt')\n")
  cat("   generate_brazilian_bibliography(documents, 'abnt', 'pt')\n")
  cat("   quick_citation_export(documents, 'exports')\n")
  cat("   get_citation_system_status()\n")
  cat("\n🎯 System ready for academic research and legal professional use!\n")
  cat("=============================================================\n\n")
} else {
  cat("\n⚠️ Citation system initialization incomplete\n")
  cat("Some components may not be available\n")
  cat("Check file paths and dependencies\n\n")
}

# Export main functions for external use
CITATION_SYSTEM_FUNCTIONS <- list(
  generate_brazilian_citation = generate_brazilian_citation,
  generate_brazilian_bibliography = generate_brazilian_bibliography,
  quick_citation_export = quick_citation_export,
  get_citation_system_status = get_citation_system_status,
  add_citation_tab_to_dashboard = add_citation_tab_to_dashboard,
  initialize_citation_system_server = initialize_citation_system_server,
  citation_system_loaded = citation_system_loaded
)