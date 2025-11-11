# URN Pattern Analysis for Unidentified Geographic Documents
# Author: Data Science Team
# Date: 2025-11-11
# Purpose: Investigate URN patterns to improve geographic extraction logic

library(DBI)
library(RPostgreSQL)
library(dplyr)
library(stringr)

# Database connection parameters
con <- dbConnect(
  PostgreSQL(),
  host = "127.0.0.1",
  port = 5433,
  dbname = "monitor_legislativo",
  user = "monitor_user",
  password = "Sdonario1"
)

cat("=============================================================\n")
cat("URN PATTERN ANALYSIS FOR UNIDENTIFIED GEOGRAPHIC DOCUMENTS\n")
cat("=============================================================\n\n")

# Total documents in database
total_docs <- dbGetQuery(con, "SELECT COUNT(*) as total FROM documents")$total
cat("Total documents in database:", format(total_docs, big.mark = ","), "\n\n")

# ============================================================
# 1. BREAKDOWN OF ALL UNIDENTIFIED CATEGORIES
# ============================================================

cat("===========================================================\n")
cat("1. BREAKDOWN OF UNIDENTIFIED CATEGORIES\n")
cat("===========================================================\n\n")

breakdown_query <- "
SELECT
    COALESCE(estado_mapeado, 'NULL') as category,
    COUNT(*) as count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as pct_of_unidentified,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM documents)::numeric, 2) as pct_of_total
FROM documents
WHERE estado_mapeado IS NULL
   OR estado_mapeado = 'Nacional'
   OR estado_mapeado = 'Estadual'
   OR estado_mapeado = 'Não Identificado'
GROUP BY estado_mapeado
ORDER BY count DESC;
"

breakdown <- dbGetQuery(con, breakdown_query)
print(breakdown, row.names = FALSE)

total_unidentified <- sum(breakdown$count)
cat("\nTotal Unidentified Documents:", format(total_unidentified, big.mark = ","), "\n")
cat("Percentage of Total Database:", round(100 * total_unidentified / total_docs, 2), "%\n\n")

# ============================================================
# 2. NACIONAL DOCUMENTS
# ============================================================

cat("===========================================================\n")
cat("2. NACIONAL DOCUMENTS\n")
cat("===========================================================\n\n")

nacional_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents WHERE estado_mapeado = 'Nacional'")$count
cat("Total Nacional documents:", format(nacional_count, big.mark = ","), "\n\n")

if (nacional_count > 0) {
  cat("Sample URNs (first 30):\n")
  cat("------------------------\n")
  nacional_urns <- dbGetQuery(con, "SELECT urn FROM documents WHERE estado_mapeado = 'Nacional' LIMIT 30")
  for (i in 1:nrow(nacional_urns)) {
    cat(sprintf("%2d. %s\n", i, nacional_urns$urn[i]))
  }
  cat("\n")
}

# ============================================================
# 3. ESTADUAL (GENERIC) DOCUMENTS
# ============================================================

cat("===========================================================\n")
cat("3. ESTADUAL (GENERIC) DOCUMENTS\n")
cat("===========================================================\n\n")

estadual_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents WHERE estado_mapeado = 'Estadual'")$count
cat("Total Estadual documents:", format(estadual_count, big.mark = ","), "\n\n")

if (estadual_count > 0) {
  cat("Sample URNs (first 30):\n")
  cat("------------------------\n")
  estadual_urns <- dbGetQuery(con, "SELECT urn FROM documents WHERE estado_mapeado = 'Estadual' LIMIT 30")
  for (i in 1:nrow(estadual_urns)) {
    cat(sprintf("%2d. %s\n", i, estadual_urns$urn[i]))
  }
  cat("\n")
}

# ============================================================
# 4. NULL ESTADO_MAPEADO
# ============================================================

cat("===========================================================\n")
cat("4. NULL ESTADO_MAPEADO DOCUMENTS\n")
cat("===========================================================\n\n")

null_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents WHERE estado_mapeado IS NULL")$count
cat("Total NULL estado_mapeado:", format(null_count, big.mark = ","), "\n\n")

if (null_count > 0) {
  cat("Sample URNs (first 30):\n")
  cat("------------------------\n")
  null_urns <- dbGetQuery(con, "SELECT urn FROM documents WHERE estado_mapeado IS NULL LIMIT 30")
  for (i in 1:nrow(null_urns)) {
    cat(sprintf("%2d. %s\n", i, null_urns$urn[i]))
  }
  cat("\n")
}

# ============================================================
# 5. NÃO IDENTIFICADO (EXPLICIT)
# ============================================================

cat("===========================================================\n")
cat("5. NÃO IDENTIFICADO (EXPLICIT) DOCUMENTS\n")
cat("===========================================================\n\n")

nao_ident_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents WHERE estado_mapeado = 'Não Identificado'")$count
cat("Total 'Não Identificado':", format(nao_ident_count, big.mark = ","), "\n\n")

if (nao_ident_count > 0) {
  cat("Sample URNs (first 30):\n")
  cat("------------------------\n")
  nao_ident_urns <- dbGetQuery(con, "SELECT urn FROM documents WHERE estado_mapeado = 'Não Identificado' LIMIT 30")
  for (i in 1:nrow(nao_ident_urns)) {
    cat(sprintf("%2d. %s\n", i, nao_ident_urns$urn[i]))
  }
  cat("\n")
}

# ============================================================
# 6. PATTERN ANALYSIS
# ============================================================

cat("===========================================================\n")
cat("6. PATTERN ANALYSIS\n")
cat("===========================================================\n\n")

analyze_patterns <- function(urns, category_name) {
  if (length(urns) == 0) return(NULL)

  cat("Pattern Analysis for:", category_name, "\n")
  cat(strrep("-", 60), "\n")

  # Extract URN components
  patterns <- data.frame(
    urn = urns,
    has_lex = grepl(":lex:", urns, fixed = TRUE),
    has_congresso = grepl(":congresso.nacional:", urns, fixed = TRUE),
    has_estado = grepl(":estado:", urns, fixed = TRUE),
    has_municipal = grepl(":municipal:", urns, fixed = TRUE),
    has_federal = grepl(":federal:", urns, fixed = TRUE),
    urn_prefix = str_extract(urns, "^urn:[^:]+:[^:]+:")
  )

  # Count patterns
  cat("\nURN Component Frequencies:\n")
  cat("  Has ':lex:' component:", sum(patterns$has_lex), "/", length(urns), "\n")
  cat("  Has ':congresso.nacional:' component:", sum(patterns$has_congresso), "/", length(urns), "\n")
  cat("  Has ':estado:' component:", sum(patterns$has_estado), "/", length(urns), "\n")
  cat("  Has ':municipal:' component:", sum(patterns$has_municipal), "/", length(urns), "\n")
  cat("  Has ':federal:' component:", sum(patterns$has_federal), "/", length(urns), "\n")

  # URN prefixes
  prefix_counts <- table(patterns$urn_prefix)
  cat("\nTop URN Prefixes:\n")
  print(head(sort(prefix_counts, decreasing = TRUE), 10))

  # Extract authority (the part after urn:lex:)
  if (any(patterns$has_lex)) {
    authorities <- str_extract(urns[patterns$has_lex], "(?<=urn:lex:)[^:]+")
    authority_counts <- table(authorities)
    cat("\nTop Authorities (after 'urn:lex:'):\n")
    print(head(sort(authority_counts, decreasing = TRUE), 10))
  }

  cat("\n")
}

# Analyze each category
if (nacional_count > 0) {
  analyze_patterns(nacional_urns$urn, "NACIONAL")
}

if (estadual_count > 0) {
  analyze_patterns(estadual_urns$urn, "ESTADUAL (GENERIC)")
}

if (null_count > 0) {
  analyze_patterns(null_urns$urn, "NULL")
}

if (nao_ident_count > 0) {
  analyze_patterns(nao_ident_urns$urn, "NÃO IDENTIFICADO")
}

# ============================================================
# 7. DETAILED PATTERN EXTRACTION
# ============================================================

cat("===========================================================\n")
cat("7. DETAILED URN STRUCTURE PATTERNS\n")
cat("===========================================================\n\n")

# Get more URNs for comprehensive pattern analysis
get_detailed_patterns <- function(category_condition, category_name, limit = 100) {
  query <- sprintf("SELECT urn FROM documents WHERE %s LIMIT %d", category_condition, limit)
  urns <- dbGetQuery(con, query)$urn

  if (length(urns) == 0) return(NULL)

  cat("\n", category_name, "- Detailed Structure Patterns:\n")
  cat(strrep("-", 60), "\n")

  # Split URNs by colons and analyze structure
  urn_parts <- strsplit(urns, ":")

  # Find common structures
  structures <- sapply(urn_parts, function(parts) {
    # Create structure pattern (first 5 parts)
    paste(head(parts, min(5, length(parts))), collapse = ":")
  })

  structure_counts <- table(structures)
  cat("\nTop URN Structures (first 5 components):\n")
  top_structures <- head(sort(structure_counts, decreasing = TRUE), 15)
  for (i in 1:length(top_structures)) {
    cat(sprintf("  %3d | %s\n", top_structures[i], names(top_structures)[i]))
  }

  # Identify geographic indicators in URNs
  geo_indicators <- list(
    federal = sum(grepl("federal", urns, ignore.case = TRUE)),
    congresso = sum(grepl("congresso", urns, ignore.case = TRUE)),
    estado = sum(grepl(":estado:", urns, fixed = TRUE)),
    municipal = sum(grepl(":municipal:", urns, fixed = TRUE)),
    br = sum(grepl(":br:", urns, fixed = TRUE)),
    state_codes = sum(grepl(":(ac|al|ap|am|ba|ce|df|es|go|ma|mt|ms|mg|pa|pb|pr|pe|pi|rj|rn|rs|ro|rr|sc|sp|se|to):", urns, ignore.case = TRUE))
  )

  cat("\nGeographic Indicators Found:\n")
  for (indicator in names(geo_indicators)) {
    cat(sprintf("  %s: %d/%d (%.1f%%)\n",
                indicator,
                geo_indicators[[indicator]],
                length(urns),
                100 * geo_indicators[[indicator]] / length(urns)))
  }

  cat("\n")
}

# Analyze detailed patterns for each category
get_detailed_patterns("estado_mapeado = 'Nacional'", "NACIONAL", 100)
get_detailed_patterns("estado_mapeado = 'Estadual'", "ESTADUAL (GENERIC)", 100)
get_detailed_patterns("estado_mapeado IS NULL", "NULL", 100)
get_detailed_patterns("estado_mapeado = 'Não Identificado'", "NÃO IDENTIFICADO", 100)

# ============================================================
# 8. RECOMMENDATIONS
# ============================================================

cat("\n")
cat("===========================================================\n")
cat("8. RECOMMENDATIONS FOR IMPROVING GEOGRAPHIC EXTRACTION\n")
cat("===========================================================\n\n")

cat("Based on the URN pattern analysis, here are recommendations:\n\n")

cat("A. NACIONAL DOCUMENTS:\n")
cat("   - Review URNs with 'congresso.nacional' or 'federal' components\n")
cat("   - These may be correctly classified as Nacional\n")
cat("   - Verify if any contain hidden state indicators\n\n")

cat("B. ESTADUAL (GENERIC) DOCUMENTS:\n")
cat("   - Extract state codes from URN structure (look for 2-letter codes)\n")
cat("   - Check for patterns like ':estado:XX:' where XX is state code\n")
cat("   - Review document titles/content for state mentions\n\n")

cat("C. NULL ESTADO_MAPEADO:\n")
cat("   - Implement fallback extraction from URN structure\n")
cat("   - Parse URN components systematically\n")
cat("   - Check for municipal URNs with embedded state info\n\n")

cat("D. GENERAL IMPROVEMENTS:\n")
cat("   - Enhance regex patterns for state code extraction\n")
cat("   - Build URN structure parser for systematic component extraction\n")
cat("   - Implement confidence scoring for geographic assignments\n")
cat("   - Create lookup table for common URN patterns\n\n")

# Close connection
dbDisconnect(con)

cat("===========================================================\n")
cat("Analysis complete!\n")
cat("===========================================================\n")
