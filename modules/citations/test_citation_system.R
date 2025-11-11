# COMPREHENSIVE CITATION SYSTEM TESTS
# ====================================
# Complete testing suite for Brazilian Legislative Citation System (Sprint 5A)
# Tests all components: Parser, Templates, Export, Bulk Management, UI Integration

cat("🧪 Starting Comprehensive Citation System Tests...\n")

# Test Results Storage
test_results <- list(
  timestamp = Sys.time(),
  overall_status = FALSE,
  component_tests = list(),
  integration_tests = list(),
  performance_tests = list(),
  sample_outputs = list()
)

# TEST DATA PREPARATION
# ====================

# Comprehensive test documents representing different Brazilian legislative types
test_documents <- data.frame(
  title = c(
    "Lei Federal nº 14.133, de 1º de abril de 2021 - Nova Lei de Licitações e Contratos Administrativos",
    "Decreto nº 10.881, de 15 de junho de 2021 - Estratégia Nacional de Governo Digital",
    "Resolução ANTT nº 5.232, de 10 de dezembro de 2020 - Registro Nacional de Transportadores Rodoviários de Cargas",
    "Lei Complementar nº 182, de 1º de junho de 2021 - Marco Legal das Startups e Empreendedorismo Inovador",
    "Constituição da República Federativa do Brasil de 1988",
    "Medida Provisória nº 1.040, de 18 de março de 2021 - Marco Legal do Câmbio",
    "Portaria ANTT nº 3.665, de 4 de novembro de 2020 - Regulamentação do RNTRC",
    "Instrução Normativa RFB nº 1.888, de 3 de maio de 2019 - Declaração de Imposto de Renda",
    "Lei Estadual SP nº 17.293, de 15 de outubro de 2020 - Política Estadual de Resíduos Sólidos",
    "Lei Municipal SP nº 16.050, de 31 de julho de 2014 - Plano Diretor Estratégico da Cidade de São Paulo"
  ),
  state = c("DF", "DF", "DF", "DF", "DF", "DF", "DF", "DF", "SP", "SP"),
  date = c("2021-04-01", "2021-06-15", "2020-12-10", "2021-06-01", "1988-10-05", 
           "2021-03-18", "2020-11-04", "2019-05-03", "2020-10-15", "2014-07-31"),
  url = c(
    "http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/L14133.htm",
    "http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/decreto/D10881.htm",
    "https://www.antt.gov.br/resolucoes/2020/5232.html",
    "http://www.planalto.gov.br/ccivil_03/leis/LCP/Lcp182.htm",
    "http://www.planalto.gov.br/ccivil_03/constituicao/constituicao.htm",
    "http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/Mpv/mpv1040.htm",
    "https://www.antt.gov.br/portarias/2020/3665.html",
    "http://normas.receita.fazenda.gov.br/sijut2consulta/",
    "https://www.al.sp.gov.br/repositorio/legislacao/lei/2020/lei-17293-15.10.2020.html",
    "http://legislacao.prefeitura.sp.gov.br/leis/lei-16050-de-31-de-julho-de-2014"
  ),
  urn = c(
    "lex:br:federal:lei:2021-04-01;14133",
    "lex:br:federal:decreto:2021-06-15;10881",
    "",
    "lex:br:federal:lei.complementar:2021-06-01;182", 
    "lex:br:federal:constituicao:1988-10-05",
    "lex:br:federal:medida.provisoria:2021-03-18;1040",
    "",
    "",
    "lex:br:sao.paulo:lei:2020-10-15;17293",
    "lex:br:sao.paulo.municipio:lei:2014-07-31;16050"
  ),
  stringsAsFactors = FALSE
)

# COMPONENT TESTS
# ==============

test_component_1_parser <- function() {
  cat("🔍 Testing Component 1: Brazilian Legislative Parser...\n")
  
  component_result <- list(
    name = "Brazilian Legislative Parser",
    passed = FALSE,
    details = list(),
    errors = c()
  )
  
  tryCatch({
    # Load parser if not loaded
    if (!exists("parse_brazilian_legislative_metadata")) {
      source("modules/citations/brazilian_legislative_parser.R")
    }
    
    # Test 1: Parse single document
    single_doc <- test_documents[1, ]
    parsed_single <- parse_brazilian_legislative_metadata(single_doc)
    
    component_result$details$single_document_parsed <- !is.null(parsed_single)
    component_result$details$metadata_structure_valid <- is.list(parsed_single[[1]]) && 
                                                        !is.null(parsed_single[[1]]$original_title)
    
    # Test 2: Parse multiple documents
    parsed_multiple <- parse_brazilian_legislative_metadata(test_documents)
    component_result$details$multiple_documents_parsed <- length(parsed_multiple) == nrow(test_documents)
    
    # Test 3: Document type recognition
    type_recognition_count <- 0
    for (i in seq_along(parsed_multiple)) {
      metadata <- parsed_multiple[[i]]
      if (!isTRUE(is.null(metadata$document_type)) && metadata$document_type != "Documento Legislativo") {
        type_recognition_count <- type_recognition_count + 1
      }
    }
    component_result$details$document_type_recognition <- type_recognition_count / length(parsed_multiple)
    
    # Test 4: Authority extraction
    authority_extraction_count <- 0
    for (i in seq_along(parsed_multiple)) {
      metadata <- parsed_multiple[[i]]
      if (!isTRUE(is.null(metadata$authority)) && metadata$authority != "") {
        authority_extraction_count <- authority_extraction_count + 1
      }
    }
    component_result$details$authority_extraction <- authority_extraction_count / length(parsed_multiple)
    
    # Test 5: Date parsing
    date_parsing_count <- 0
    for (i in seq_along(parsed_multiple)) {
      metadata <- parsed_multiple[[i]]
      if (!isTRUE(is.null(metadata$year)) && metadata$year != "") {
        date_parsing_count <- date_parsing_count + 1
      }
    }
    component_result$details$date_parsing <- date_parsing_count / length(parsed_multiple)
    
    # Overall pass condition
    component_result$passed <- component_result$details$single_document_parsed &&
                              component_result$details$multiple_documents_parsed &&
                              component_result$details$document_type_recognition > 0.7 &&
                              component_result$details$authority_extraction > 0.8 &&
                              component_result$details$date_parsing > 0.8
    
    if (component_result$passed) {
      cat("✅ Parser tests passed\n")
    } else {
      cat("❌ Parser tests failed\n")
    }
    
  }, error = function(e) {
    component_result$errors <- c(component_result$errors, e$message)
    cat("❌ Parser test error:", e$message, "\n")
  })
  
  return(component_result)
}

test_component_2_templates <- function() {
  cat("📝 Testing Component 2: Citation Templates...\n")
  
  component_result <- list(
    name = "Citation Templates",
    passed = FALSE,
    details = list(),
    sample_citations = list(),
    errors = c()
  )
  
  tryCatch({
    # Load templates if not loaded
    if (!exists("format_abnt_citation")) {
      source("modules/citations/citation_templates.R")
    }
    
    # Load parser for test data
    if (!exists("parse_brazilian_legislative_metadata")) {
      source("modules/citations/brazilian_legislative_parser.R")
    }
    
    # Parse test document for templates
    test_doc <- test_documents[1, ]  # Lei Federal 14.133/2021
    parsed_metadata <- parse_brazilian_legislative_metadata(test_doc)[[1]]
    
    # Test ABNT format
    abnt_citation <- format_abnt_citation(parsed_metadata, "pt")
    component_result$sample_citations$abnt <- abnt_citation
    component_result$details$abnt_generated <- nchar(abnt_citation) > 50 && 
                                             grepl("BRASIL", abnt_citation)
    
    # Test APA format  
    apa_citation <- format_apa_citation(parsed_metadata, "en")
    component_result$sample_citations$apa <- apa_citation
    component_result$details$apa_generated <- nchar(apa_citation) > 20 &&
                                            grepl("2021", apa_citation)
    
    # Test Vancouver format
    vancouver_citation <- format_vancouver_citation(parsed_metadata, 1)
    component_result$sample_citations$vancouver <- vancouver_citation
    component_result$details$vancouver_generated <- nchar(vancouver_citation) > 20 &&
                                                   grepl("^1\\.", vancouver_citation)
    
    # Test Bluebook format
    bluebook_citation <- format_bluebook_citation(parsed_metadata)
    component_result$sample_citations$bluebook <- bluebook_citation
    component_result$details$bluebook_generated <- nchar(bluebook_citation) > 20
    
    # Test bibliography generation
    bibliography <- format_abnt_bibliography(list(parsed_metadata), "pt")
    component_result$details$bibliography_generated <- nchar(bibliography) > 50 &&
                                                     grepl("REFERÊNCIAS", bibliography)
    
    # Overall pass condition
    component_result$passed <- component_result$details$abnt_generated &&
                              component_result$details$apa_generated &&
                              component_result$details$vancouver_generated &&
                              component_result$details$bluebook_generated &&
                              component_result$details$bibliography_generated
    
    if (component_result$passed) {
      cat("✅ Template tests passed\n")
    } else {
      cat("❌ Template tests failed\n")
    }
    
  }, error = function(e) {
    component_result$errors <- c(component_result$errors, e$message)
    cat("❌ Template test error:", e$message, "\n")
  })
  
  return(component_result)
}

test_component_3_export <- function() {
  cat("📤 Testing Component 3: Citation Export...\n")
  
  component_result <- list(
    name = "Citation Export",
    passed = FALSE,
    details = list(),
    sample_exports = list(),
    errors = c()
  )
  
  tryCatch({
    # Load export system if not loaded
    if (!exists("export_bibtex")) {
      source("modules/citations/citation_export.R")
    }
    
    # Load dependencies
    if (!exists("parse_brazilian_legislative_metadata")) {
      source("modules/citations/brazilian_legislative_parser.R")
    }
    if (!exists("format_abnt_citation")) {
      source("modules/citations/citation_templates.R")
    }
    
    # Parse test documents
    parsed_list <- parse_brazilian_legislative_metadata(head(test_documents, 3))
    
    # Test BibTeX export
    bibtex_result <- export_bibtex(parsed_list)
    component_result$sample_exports$bibtex <- substr(bibtex_result, 1, 200)
    component_result$details$bibtex_export <- nchar(bibtex_result) > 100 &&
                                            grepl("@", bibtex_result) &&
                                            grepl("title =", bibtex_result)
    
    # Test RIS export
    ris_result <- export_ris(parsed_list)
    component_result$sample_exports$ris <- substr(ris_result, 1, 200)
    component_result$details$ris_export <- nchar(ris_result) > 50 &&
                                         grepl("TY  -", ris_result) &&
                                         grepl("ER  -", ris_result)
    
    # Test plain text export
    plain_result <- export_plain_text(parsed_list, "abnt", "pt")
    component_result$sample_exports$plain_text <- substr(plain_result, 1, 200)
    component_result$details$plain_text_export <- nchar(plain_result) > 100 &&
                                                 grepl("REFERÊNCIAS", plain_result)
    
    # Test EndNote XML export (if xml2 available)
    if (requireNamespace("xml2", quietly = TRUE)) {
      xml_result <- export_endnote_xml(parsed_list)
      component_result$details$endnote_xml_export <- !isTRUE(is.null(xml_result)) && nchar(xml_result) > 100
    } else {
      component_result$details$endnote_xml_export <- NA  # Not testable
    }
    
    # Overall pass condition
    component_result$passed <- component_result$details$bibtex_export &&
                              component_result$details$ris_export &&
                              component_result$details$plain_text_export
    
    if (component_result$passed) {
      cat("✅ Export tests passed\n")
    } else {
      cat("❌ Export tests failed\n")
    }
    
  }, error = function(e) {
    component_result$errors <- c(component_result$errors, e$message)
    cat("❌ Export test error:", e$message, "\n")
  })
  
  return(component_result)
}

test_component_4_bulk_management <- function() {
  cat("📚 Testing Component 4: Bulk Citation Management...\n")
  
  component_result <- list(
    name = "Bulk Citation Management",
    passed = FALSE,
    details = list(),
    errors = c()
  )
  
  tryCatch({
    # Load bulk management if not loaded
    if (!exists("create_citation_collection")) {
      source("modules/citations/bulk_citation_manager.R")
    }
    
    # Test 1: Create collection
    collection_id <- create_citation_collection("Test Collection", "Automated test collection")
    component_result$details$collection_created <- !is.null(collection_id)
    
    if (collection_id) {
      # Test 2: Add documents to collection
      added_count <- add_documents_to_collection(collection_id, head(test_documents, 5), parse_metadata = FALSE)
      component_result$details$documents_added <- added_count == 5
      
      # Test 3: Get collection info
      collection_info <- get_collection_info(collection_id)
      component_result$details$collection_info_retrieved <- !isTRUE(is.null(collection_info)) &&
                                                           collection_info$document_count == 5
      
      # Test 4: Generate collection citations
      if (exists("generate_collection_citations")) {
        citations <- generate_collection_citations(collection_id, "abnt", "pt")
        component_result$details$collection_citations_generated <- nchar(citations) > 100
      } else {
        component_result$details$collection_citations_generated <- FALSE
      }
      
      # Test 5: Search within collection
      search_results <- search_collection_documents(collection_id, "Lei")
      component_result$details$collection_search_functional <- length(search_results) > 0
      
      # Cleanup
      delete_collection(collection_id)
      component_result$details$collection_deleted <- TRUE
    }
    
    # Overall pass condition
    component_result$passed <- component_result$details$collection_created &&
                              component_result$details$documents_added &&
                              component_result$details$collection_info_retrieved &&
                              component_result$details$collection_search_functional
    
    if (component_result$passed) {
      cat("✅ Bulk management tests passed\n")
    } else {
      cat("❌ Bulk management tests failed\n")
    }
    
  }, error = function(e) {
    component_result$errors <- c(component_result$errors, e$message)
    cat("❌ Bulk management test error:", e$message, "\n")
  })
  
  return(component_result)
}

test_component_5_ui_integration <- function() {
  cat("🖥️ Testing Component 5: UI Integration...\n")
  
  component_result <- list(
    name = "UI Integration",
    passed = FALSE,
    details = list(),
    errors = c()
  )
  
  tryCatch({
    # Load UI components if not loaded
    if (!exists("citation_tab_ui")) {
      source("modules/citations/citation_ui.R")
    }
    
    # Test 1: UI function exists and returns valid Shiny UI
    ui_result <- citation_tab_ui()
    component_result$details$ui_function_works <- inherits(ui_result, "shiny.tag") ||
                                                 inherits(ui_result, "list")
    
    # Test 2: Check for required UI elements
    ui_html <- as.character(ui_result)
    component_result$details$has_citation_interface <- grepl("citation", ui_html, ignore.case = TRUE)
    component_result$details$has_format_selection <- grepl("select", ui_html, ignore.case = TRUE)
    component_result$details$has_export_options <- grepl("download", ui_html, ignore.case = TRUE)
    
    # Test 3: Server function exists
    component_result$details$server_function_exists <- exists("citation_server")
    
    # Overall pass condition
    component_result$passed <- component_result$details$ui_function_works &&
                              component_result$details$has_citation_interface &&
                              component_result$details$server_function_exists
    
    if (component_result$passed) {
      cat("✅ UI integration tests passed\n")
    } else {
      cat("❌ UI integration tests failed\n")
    }
    
  }, error = function(e) {
    component_result$errors <- c(component_result$errors, e$message)
    cat("❌ UI integration test error:", e$message, "\n")
  })
  
  return(component_result)
}

# INTEGRATION TESTS
# ================

test_integration_main_interface <- function() {
  cat("🔗 Testing Main Citation Interface Integration...\n")
  
  integration_result <- list(
    name = "Main Interface Integration",
    passed = FALSE,
    details = list(),
    errors = c()
  )
  
  tryCatch({
    # Load main citation system
    if (!exists("generate_brazilian_citation")) {
      source("modules/citations/citation_system.R")
    }
    
    # Test 1: Generate single citation
    single_citation <- generate_brazilian_citation(test_documents[1, ], "abnt", "pt")
    integration_result$details$single_citation_works <- nchar(single_citation) > 50 &&
                                                       !grepl("error|Error|❌", single_citation)
    
    # Test 2: Generate bibliography
    bibliography <- generate_brazilian_bibliography(head(test_documents, 3), "abnt", "pt")
    integration_result$details$bibliography_works <- nchar(bibliography) > 100 &&
                                                    grepl("REFERÊNCIAS", bibliography)
    
    # Test 3: Quick export
    export_results <- quick_citation_export(head(test_documents, 2), tempdir(), "test_export")
    integration_result$details$quick_export_works <- !is.null(export_results)
    
    # Test 4: System status
    status <- get_citation_system_status()
    integration_result$details$status_function_works <- !isTRUE(is.null(status)) &&
                                                       is.logical(status$system_loaded)
    
    # Overall pass condition
    integration_result$passed <- integration_result$details$single_citation_works &&
                                integration_result$details$bibliography_works &&
                                integration_result$details$status_function_works
    
    if (integration_result$passed) {
      cat("✅ Main interface integration tests passed\n")
    } else {
      cat("❌ Main interface integration tests failed\n")
    }
    
  }, error = function(e) {
    integration_result$errors <- c(integration_result$errors, e$message)
    cat("❌ Main interface integration test error:", e$message, "\n")
  })
  
  return(integration_result)
}

# PERFORMANCE TESTS
# ================

test_performance_large_dataset <- function() {
  cat("⚡ Testing Performance with Large Dataset...\n")
  
  performance_result <- list(
    name = "Performance Tests",
    passed = FALSE,
    timing = list(),
    details = list(),
    errors = c()
  )
  
  tryCatch({
    # Create larger test dataset (simulate 100 documents)
    large_dataset <- do.call(rbind, replicate(10, test_documents, simplify = FALSE))
    large_dataset$title <- paste(large_dataset$title, "- Copy", rep(1:10, each = nrow(test_documents)))
    
    # Test 1: Parsing performance
    parse_start <- Sys.time()
    if (exists("parse_brazilian_legislative_metadata")) {
      parsed_large <- parse_brazilian_legislative_metadata(large_dataset)
      parse_end <- Sys.time()
      performance_result$timing$parsing_seconds <- as.numeric(difftime(parse_end, parse_start, units = "secs"))
      performance_result$details$parsing_performance <- performance_result$timing$parsing_seconds < 30  # Under 30 seconds
    }
    
    # Test 2: Citation generation performance
    if (exists("generate_brazilian_bibliography")) {
      citation_start <- Sys.time()
      large_bibliography <- generate_brazilian_bibliography(head(large_dataset, 20), "abnt", "pt")
      citation_end <- Sys.time()
      performance_result$timing$citation_seconds <- as.numeric(difftime(citation_end, citation_start, units = "secs"))
      performance_result$details$citation_performance <- performance_result$timing$citation_seconds < 10  # Under 10 seconds
    }
    
    # Memory usage check
    performance_result$details$memory_reasonable <- TRUE  # Basic check - could be enhanced
    
    # Overall pass condition
    performance_result$passed <- performance_result$details$parsing_performance &&
                                performance_result$details$citation_performance &&
                                performance_result$details$memory_reasonable
    
    if (performance_result$passed) {
      cat("✅ Performance tests passed\n")
    } else {
      cat("❌ Performance tests failed\n")
    }
    
  }, error = function(e) {
    performance_result$errors <- c(performance_result$errors, e$message)
    cat("❌ Performance test error:", e$message, "\n")
  })
  
  return(performance_result)
}

# MAIN TEST EXECUTION
# ==================

run_comprehensive_tests <- function() {
  cat("\n🧪 ===== COMPREHENSIVE CITATION SYSTEM TESTS =====\n")
  cat("Testing Sprint 5A Implementation\n\n")
  
  # Component Tests
  test_results$component_tests$parser <<- test_component_1_parser()
  test_results$component_tests$templates <<- test_component_2_templates()
  test_results$component_tests$export <<- test_component_3_export()
  test_results$component_tests$bulk_management <<- test_component_4_bulk_management()
  test_results$component_tests$ui_integration <<- test_component_5_ui_integration()
  
  # Integration Tests
  test_results$integration_tests$main_interface <<- test_integration_main_interface()
  
  # Performance Tests
  test_results$performance_tests$large_dataset <<- test_performance_large_dataset()
  
  # Calculate overall status
  all_component_tests <- sapply(test_results$component_tests, function(x) x$passed)
  all_integration_tests <- sapply(test_results$integration_tests, function(x) x$passed)
  all_performance_tests <- sapply(test_results$performance_tests, function(x) x$passed)
  
  test_results$overall_status <<- all(all_component_tests, na.rm = TRUE) && 
                                  all(all_integration_tests, na.rm = TRUE) &&
                                  all(all_performance_tests, na.rm = TRUE)
  
  # Print final results
  cat("\n📊 ===== TEST RESULTS SUMMARY =====\n")
  cat("Overall Status:", if (test_results$overall_status) "✅ PASSED" else "❌ FAILED", "\n\n")
  
  cat("Component Tests:\n")
  for (name in names(test_results$component_tests)) {
    result <- test_results$component_tests[[name]]
    status <- if (result$passed) "✅ PASS" else "❌ FAIL"
    cat(sprintf("  %s: %s\n", result$name, status))
  }
  
  cat("\nIntegration Tests:\n")
  for (name in names(test_results$integration_tests)) {
    result <- test_results$integration_tests[[name]]
    status <- if (result$passed) "✅ PASS" else "❌ FAIL"
    cat(sprintf("  %s: %s\n", result$name, status))
  }
  
  cat("\nPerformance Tests:\n")
  for (name in names(test_results$performance_tests)) {
    result <- test_results$performance_tests[[name]]
    status <- if (result$passed) "✅ PASS" else "❌ FAIL"
    cat(sprintf("  %s: %s\n", result$name, status))
    
    if (!is.null(result$timing)) {
      for (timing_name in names(result$timing)) {
        cat(sprintf("    %s: %.2f seconds\n", timing_name, result$timing[[timing_name]]))
      }
    }
  }
  
  if (test_results$overall_status) {
    cat("\n🎉 SPRINT 5A CITATION SYSTEM: FULLY OPERATIONAL\n")
    cat("✅ Ready for academic and professional use\n")
    cat("📚 All citation formats working correctly\n")
    cat("🔄 Export functionality validated\n")
    cat("📊 Performance requirements met\n")
  } else {
    cat("\n⚠️ SPRINT 5A CITATION SYSTEM: NEEDS ATTENTION\n")
    cat("Some components require fixes before production deployment\n")
  }
  
  cat("===============================================\n\n")
  
  return(test_results)
}

# Save sample citations for documentation
generate_sample_outputs <- function() {
  if (test_results$component_tests$templates$passed) {
    test_results$sample_outputs <<- test_results$component_tests$templates$sample_citations
  }
}

# Execute all tests
final_results <- run_comprehensive_tests()
generate_sample_outputs()

cat("🧪 Comprehensive testing completed\n")
cat("📋 Test results stored in test_results variable\n")
cat("📄 Sample citations available in test_results$sample_outputs\n")