# Municipality Investigation Summary - Brazilian Legislative Database
# Statistical analysis and visualization of municipality data findings

# Load required libraries (basic ones that should be available)
library(base)

# Read the CSV files created by Python analysis
if (file.exists("existing_municipalities.csv")) {
  cat("Reading existing municipalities data...\n")
  existing_munis <- read.csv("existing_municipalities.csv", stringsAsFactors = FALSE)
  print(head(existing_munis))
  print(paste("Found", nrow(existing_munis), "existing municipalities"))
} else {
  cat("No existing municipalities file found\n")
  existing_munis <- data.frame()
}

if (file.exists("text_mining_municipalities.csv")) {
  cat("Reading text mining results...\n") 
  text_mining_munis <- read.csv("text_mining_municipalities.csv", stringsAsFactors = FALSE)
  print(paste("Found", nrow(text_mining_munis), "text mining results"))
  
  # Show sample of what was found
  cat("\nSample text mining results:\n")
  if (nrow(text_mining_munis) > 0) {
    print(head(text_mining_munis$municipality, 20))
  }
} else {
  cat("No text mining results file found\n")
  text_mining_munis <- data.frame()
}

# Known Brazilian municipalities for validation
known_municipalities <- c(
  "São Paulo", "Rio de Janeiro", "Brasília", "Salvador", "Fortaleza", 
  "Belo Horizonte", "Manaus", "Curitiba", "Recife", "Porto Alegre",
  "Goiânia", "Belém", "Guarulhos", "Campinas", "São Luís", "Maceió",
  "Campo Grande", "Teresina", "São Gonçalo", "Nova Iguaçu", "Natal",
  "Contagem", "São José dos Campos", "Ribeirão Preto", "Santos", 
  "Uberlândia", "Sorocaba", "Osasco", "João Pessoa", "Jaboatão dos Guararapes",
  "Catanduva", "Bauru", "Araraquara", "Piracicaba", "Franca", "Taubaté",
  "Santos", "São Vicente", "Diadema", "Santo André", "São Bernardo do Campo",
  "São Caetano do Sul", "Mauá", "Blumenau", "Joinville", "Florianópolis"
)

cat("\n" , rep("=", 60), "\n")
cat("MUNICIPALITY DATA INVESTIGATION SUMMARY\n")
cat(rep("=", 60), "\n")

# Summary statistics
total_documents <- 134014
documents_with_existing_muni <- 2994

cat("\nDATABASE OVERVIEW:\n")
cat("- Total documents in database:", total_documents, "\n")
cat("- Documents with existing municipality field:", documents_with_existing_muni, "\n")
cat("- Existing municipality coverage:", 
    round((documents_with_existing_muni / total_documents) * 100, 2), "%\n")

# Analyze existing municipality data
if (nrow(existing_munis) > 0) {
  cat("\nEXISTING MUNICIPALITY FIELD ANALYSIS:\n")
  cat("- Unique municipalities in existing field:", nrow(existing_munis), "\n")
  
  if ("municipality" %in% names(existing_munis) && "document_count" %in% names(existing_munis)) {
    cat("- Top municipalities by document count:\n")
    existing_sorted <- existing_munis[order(existing_munis$document_count, decreasing = TRUE), ]
    for (i in 1:min(10, nrow(existing_sorted))) {
      cat("  ", i, ". ", existing_sorted$municipality[i], ": ", 
          existing_sorted$document_count[i], " documents\n", sep = "")
    }
  }
}

# Analyze text mining results (with caution due to false positives)
if (nrow(text_mining_munis) > 0) {
  cat("\nTEXT MINING ANALYSIS:\n")
  cat("- Total text mining results:", nrow(text_mining_munis), "\n")
  
  # Check how many are likely valid (basic validation)
  likely_valid <- 0
  if ("municipality" %in% names(text_mining_munis)) {
    for (muni in text_mining_munis$municipality) {
      # Basic validation - not too long, not all caps legal text
      if (nchar(muni) >= 3 && nchar(muni) <= 30 && 
          !grepl("^[A-Z ]+$", muni) && 
          !grepl("\\d{3,}", muni) &&
          !grepl("^(A |O |DE |DO |DA |EM |COM |PARA |POR )", muni)) {
        likely_valid <- likely_valid + 1
      }
    }
  }
  
  cat("- Estimated valid municipalities from text mining:", likely_valid, "\n")
  
  # Check for known municipalities
  if ("municipality" %in% names(text_mining_munis)) {
    known_found <- intersect(text_mining_munis$municipality, known_municipalities)
    if (length(known_found) > 0) {
      cat("- Known major municipalities found in text mining:\n")
      for (known in known_found) {
        cat("  ✓ ", known, "\n", sep = "")
      }
    }
  }
}

# Overall coverage estimate
total_with_municipality <- documents_with_existing_muni
if (exists("likely_valid")) {
  total_with_municipality <- documents_with_existing_muni + likely_valid
}

coverage_percent <- (total_with_municipality / total_documents) * 100

cat("\n", rep("=", 40), "\n")
cat("FINAL COVERAGE ESTIMATE\n")
cat(rep("=", 40), "\n")
cat("- Documents with existing municipality data:", documents_with_existing_muni, "\n")
if (exists("likely_valid")) {
  cat("- Estimated additional from text mining:", likely_valid, "\n")
}
cat("- Total estimated municipality coverage:", total_with_municipality, "\n")
cat("- Overall coverage percentage:", round(coverage_percent, 2), "%\n")

# Key findings
cat("\n", rep("=", 50), "\n")
cat("KEY FINDINGS\n")
cat(rep("=", 50), "\n")

cat("1. CURRENT STATE:\n")
cat("   - Only", documents_with_existing_muni, "out of", total_documents, "documents have municipality data\n")
cat("   - This represents just", round((documents_with_existing_muni/total_documents)*100, 1), "% coverage\n")
cat("   - The existing field contains primarily 'Brasília' (federal documents)\n")

cat("\n2. TEXT MINING POTENTIAL:\n") 
cat("   - Text mining patterns identified thousands of potential matches\n")
cat("   - However, most are false positives due to legal text complexity\n")
cat("   - Genuine municipalities are embedded in legal language\n")

cat("\n3. DATA QUALITY CHALLENGES:\n")
cat("   - Legal documents use complex language that generates false positives\n")
cat("   - Many documents are federal-level and naturally lack municipality info\n")
cat("   - Municipal-specific documents are a minority in this database\n")

cat("\n4. RECOMMENDATIONS:\n")
cat("   - Focus on documents with 'Prefeitura', 'Câmara Municipal' in titles\n")
cat("   - Parse jurisdiction field more carefully for locality info\n")
cat("   - Consider manual validation for high-precision municipality extraction\n")
cat("   - Geographic focus may be limited due to federal nature of much content\n")

# Save summary
summary_text <- paste(
  "Municipality Investigation Summary",
  "================================",
  paste("Total documents:", total_documents),
  paste("Documents with municipality field:", documents_with_existing_muni),
  paste("Coverage percentage:", round((documents_with_existing_muni/total_documents)*100, 2), "%"),
  "",
  "Key Finding: The database is primarily federal-level documents with limited",
  "municipality-specific content. Only ~2,994 documents have explicit municipality",
  "data, mostly 'Brasília'. Text mining reveals potential but with high noise.",
  "",
  "The investigation confirms that municipality data is sparse in this dataset,",
  "which appears to focus on federal legislation and jurisprudence rather than",
  "municipal-level legal documents.",
  sep = "\n"
)

writeLines(summary_text, "municipality_investigation_summary.txt")

cat("\n✅ Analysis completed. Summary saved to 'municipality_investigation_summary.txt'\n")