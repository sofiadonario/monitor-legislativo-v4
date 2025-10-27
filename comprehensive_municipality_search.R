# ============================================================================
# COMPREHENSIVE MUNICIPALITY SEARCH - R ANALYSIS
# ============================================================================
# This script performs a comprehensive search for municipality patterns in
# combined formats using R for better text processing and database connectivity
# ============================================================================

# Load required libraries
suppressPackageStartupMessages({
  library(dplyr)
  library(stringr)
  library(readr)
  library(DBI)
  library(RPostgres)
})

# Brazilian state abbreviations
BRAZILIAN_STATES <- c('AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                      'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                      'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO')

cat("🚀 COMPREHENSIVE MUNICIPALITY SEARCH STARTING...\n")
cat(paste(rep("=", 60), collapse=""), "\n")

# ============================================================================
# FUNCTION: Search for municipality patterns in text
# ============================================================================

search_municipality_patterns <- function(text_vector, field_name = "unknown") {
  if (length(text_vector) == 0) return(data.frame())
  
  # Remove NA values
  text_vector <- text_vector[!is.na(text_vector)]
  if (length(text_vector) == 0) return(data.frame())
  
  results <- data.frame(
    original_text = character(),
    city = character(),
    state = character(),
    pattern_type = character(),
    field_name = character(),
    stringsAsFactors = FALSE
  )
  
  cat(sprintf("  🔍 Searching %s field with %d records...\n", field_name, length(text_vector)))
  
  for (text in text_vector) {
    if (isTRUE(is.na(text)) || nchar(text) < 5) next
    
    # 1. Dash patterns: "City - SP"
    dash_match <- str_match(text, "^(.+?)\\s*-\\s*([A-Z]{2})$")
    if (!is.na(dash_match[1])) {
      city <- str_trim(dash_match[2])
      state <- dash_match[3]
      if (state %in% BRAZILIAN_STATES && nchar(city) > 2 && is_valid_city_name(city)) {
        results <- rbind(results, data.frame(
          original_text = text,
          city = city,
          state = state,
          pattern_type = "dash_pattern",
          field_name = field_name,
          stringsAsFactors = FALSE
        ))
      }
    }
    
    # 2. Parentheses patterns: "City (SP)"
    paren_match <- str_match(text, "^(.+?)\\s*\\(([A-Z]{2})\\)$")
    if (!is.na(paren_match[1])) {
      city <- str_trim(paren_match[2])
      state <- paren_match[3]
      if (state %in% BRAZILIAN_STATES && nchar(city) > 2 && is_valid_city_name(city)) {
        results <- rbind(results, data.frame(
          original_text = text,
          city = city,
          state = state,
          pattern_type = "parentheses_pattern",
          field_name = field_name,
          stringsAsFactors = FALSE
        ))
      }
    }
    
    # 3. Comma patterns: "City, SP"
    comma_match <- str_match(text, "^(.+?),\\s*([A-Z]{2})$")
    if (!is.na(comma_match[1])) {
      city <- str_trim(comma_match[2])
      state <- comma_match[3]
      if (state %in% BRAZILIAN_STATES && nchar(city) > 2 && is_valid_city_name(city)) {
        results <- rbind(results, data.frame(
          original_text = text,
          city = city,
          state = state,
          pattern_type = "comma_pattern",
          field_name = field_name,
          stringsAsFactors = FALSE
        ))
      }
    }
    
    # 4. Authority patterns: "Prefeitura de City"
    prefeitura_match <- str_match(text, "(?i)Prefeitura\\s+(Municipal\\s+)?de\\s+(.+?)(?:\\s*[-,(]|$)")
    if (!is.na(prefeitura_match[1])) {
      city <- str_trim(prefeitura_match[3])
      if (nchar(city) > 2 && is_valid_city_name(city)) {
        results <- rbind(results, data.frame(
          original_text = text,
          city = city,
          state = "Unknown",
          pattern_type = "prefeitura_pattern",
          field_name = field_name,
          stringsAsFactors = FALSE
        ))
      }
    }
    
    # 5. Câmara patterns: "Câmara Municipal de City"
    camara_match <- str_match(text, "(?i)Câmara\\s+Municipal\\s+de\\s+(.+?)(?:\\s*[-,(]|$)")
    if (!is.na(camara_match[1])) {
      city <- str_trim(camara_match[2])
      if (nchar(city) > 2 && is_valid_city_name(city)) {
        results <- rbind(results, data.frame(
          original_text = text,
          city = city,
          state = "Unknown",
          pattern_type = "camara_pattern",
          field_name = field_name,
          stringsAsFactors = FALSE
        ))
      }
    }
  }
  
  cat(sprintf("    ✅ Found %d municipality patterns\n", nrow(results)))
  return(results)
}

# ============================================================================
# FUNCTION: Validate city names
# ============================================================================

is_valid_city_name <- function(city_name) {
  if (isTRUE(is.na(city_name)) || nchar(city_name) < 2) return(FALSE)
  
  # Exclude obvious non-city words
  exclude_patterns <- c("(?i)lei", "(?i)decreto", "(?i)portaria", "(?i)resolução",
                       "(?i)instrução", "(?i)federal", "(?i)nacional", "(?i)brasil",
                       "(?i)república", "(?i)união", "(?i)art", "(?i)artigo",
                       "(?i)inciso", "(?i)parágrafo", "(?i)anexo", "\\d{4}")
  
  for (pattern in exclude_patterns) {
    if (str_detect(city_name, pattern)) return(FALSE)
  }
  
  # Must start with capital letter
  if (!str_detect(city_name, "^[A-ZÁÇÃÕÍÉÓÚÀÂÊÔÜ]")) return(FALSE)
  
  return(TRUE)
}

# ============================================================================
# FUNCTION: Load database connection
# ============================================================================

get_database_connection <- function() {
  tryCatch({
    # Try to source the database connection
    source("RAILWAY_PRODUCTION_DB_FIX.R", local = TRUE)
    
    # Test if connection functions exist
    if (exists("get_railway_connection", envir = .GlobalEnv)) {
      conn <- get_railway_connection()
      if (!is.null(conn)) {
        cat("✅ Database connection established\n")
        return(conn)
      }
    }
    
    cat("⚠️ Database connection not available, using CSV fallback\n")
    return(NULL)
  }, error = function(e) {
    cat("⚠️ Database connection failed:", e$message, "\n")
    return(NULL)
  })
}

# ============================================================================
# FUNCTION: Search in database
# ============================================================================

search_database_patterns <- function(conn) {
  if (is.null(conn)) return(data.frame())
  
  cat("📊 Searching database for municipality patterns...\n")
  
  tryCatch({
    # Query to get relevant fields
    query <- "
    SELECT DISTINCT 
      municipality,
      locality,
      authority,
      titulo as title,
      estado
    FROM documents 
    WHERE (municipality IS NOT NULL AND municipality != '') 
       OR (locality IS NOT NULL AND locality != '')
       OR (authority IS NOT NULL AND authority != '')
       OR (titulo IS NOT NULL AND titulo != '')
    LIMIT 50000;
    "
    
    data <- dbGetQuery(conn, query)
    cat(sprintf("📊 Retrieved %d records from database\n", nrow(data)))
    
    all_results <- data.frame()
    
    # Search each field
    if ("municipality" %in% names(data) && sum(!is.na(data$municipality)) > 0) {
      municipality_results <- search_municipality_patterns(data$municipality, "municipality")
      all_results <- rbind(all_results, municipality_results)
    }
    
    if ("locality" %in% names(data) && sum(!is.na(data$locality)) > 0) {
      locality_results <- search_municipality_patterns(data$locality, "locality")
      all_results <- rbind(all_results, locality_results)
    }
    
    if ("authority" %in% names(data) && sum(!is.na(data$authority)) > 0) {
      authority_results <- search_municipality_patterns(data$authority, "authority")
      all_results <- rbind(all_results, authority_results)
    }
    
    if ("title" %in% names(data) && sum(!is.na(data$title)) > 0) {
      title_results <- search_municipality_patterns(data$title, "title")
      all_results <- rbind(all_results, title_results)
    }
    
    return(all_results)
    
  }, error = function(e) {
    cat("❌ Database search error:", e$message, "\n")
    return(data.frame())
  })
}

# ============================================================================
# FUNCTION: Search CSV files
# ============================================================================

search_csv_files <- function() {
  cat("📁 Searching CSV files for municipality patterns...\n")
  
  # Find relevant CSV files
  csv_files <- list.files(".", pattern = "\\.csv$", recursive = TRUE, full.names = TRUE)
  
  # Filter for relevant files
  relevant_files <- csv_files[str_detect(csv_files, "(?i)(lexml|municipal|legisla|juridic|doutrin|proposic)")]
  
  if (length(relevant_files) == 0) {
    cat("⚠️ No relevant CSV files found\n")
    return(data.frame())
  }
  
  cat(sprintf("📊 Found %d relevant CSV files\n", length(relevant_files)))
  
  all_csv_results <- data.frame()
  
  for (file in head(relevant_files, 10)) {  # Limit to first 10 files
    tryCatch({
      cat(sprintf("  📄 Analyzing %s...\n", basename(file)))
      
      # Try to read the file
      data <- read_csv(file, locale = locale(encoding = "UTF-8"), show_col_types = FALSE)
      
      if (nrow(data) == 0) next
      
      # Find relevant columns
      relevant_cols <- names(data)[str_detect(tolower(names(data)), 
        "(municipal|localidade|cidade|autoridade|jurisdic|titulo|local|authority|municipality|locality)")]
      
      if (length(relevant_cols) == 0) next
      
      cat(sprintf("    🎯 Analyzing columns: %s\n", paste(relevant_cols, collapse = ", ")))
      
      # Search each relevant column
      for (col in relevant_cols) {
        if (col %in% names(data)) {
          col_results <- search_municipality_patterns(data[[col]], col)
          all_csv_results <- rbind(all_csv_results, col_results)
        }
      }
      
    }, error = function(e) {
      cat(sprintf("  ⚠️ Error reading %s: %s\n", basename(file), e$message))
    })
  }
  
  return(all_csv_results)
}

# ============================================================================
# MAIN ANALYSIS
# ============================================================================

main_analysis <- function() {
  # Initialize results
  all_results <- data.frame()
  
  # 1. Try database search first
  conn <- get_database_connection()
  if (!is.null(conn)) {
    db_results <- search_database_patterns(conn)
    all_results <- rbind(all_results, db_results)
    dbDisconnect(conn)
  }
  
  # 2. Search CSV files
  csv_results <- search_csv_files()
  all_results <- rbind(all_results, csv_results)
  
  # 3. Remove duplicates
  if (nrow(all_results) > 0) {
    all_results <- all_results %>%
      distinct(city, state, pattern_type, .keep_all = TRUE) %>%
      arrange(state, city)
  }
  
  return(all_results)
}

# ============================================================================
# GENERATE REPORT
# ============================================================================

generate_report <- function(results) {
  if (nrow(results) == 0) {
    cat("❌ No municipality patterns found!\n")
    return()
  }
  
  cat("\n", paste(rep("=", 80), collapse=""), "\n")
  cat("COMPREHENSIVE MUNICIPALITY SEARCH RESULTS\n")
  cat(paste(rep("=", 80), collapse=""), "\n")
  
  # Overall summary
  cat("📊 OVERALL SUMMARY:\n")
  cat(sprintf("   • Total municipality patterns found: %d\n", nrow(results)))
  cat(sprintf("   • Unique municipalities: %d\n", n_distinct(paste(results$city, results$state))))
  cat(sprintf("   • States represented: %d\n", n_distinct(results$state[results$state != "Unknown"])))
  
  # By pattern type
  cat("\n🔍 PATTERNS BY TYPE:\n")
  pattern_summary <- results %>%
    count(pattern_type, sort = TRUE)
  for (i in 1:nrow(pattern_summary)) {
    cat(sprintf("   • %s: %d\n", str_to_title(str_replace_all(pattern_summary$pattern_type[i], "_", " ")), pattern_summary$n[i]))
  }
  
  # By field
  cat("\n📋 PATTERNS BY FIELD:\n")
  field_summary <- results %>%
    count(field_name, sort = TRUE)
  for (i in 1:nrow(field_summary)) {
    cat(sprintf("   • %s: %d\n", field_summary$field_name[i], field_summary$n[i]))
  }
  
  # By state
  cat("\n🏛️ BY STATE:\n")
  state_summary <- results %>%
    filter(state != "Unknown") %>%
    count(state, sort = TRUE)
  for (i in 1:min(10, nrow(state_summary))) {
    cat(sprintf("   • %s: %d municipalities\n", state_summary$state[i], state_summary$n[i]))
  }
  
  # Top municipalities
  cat("\n🏙️ MUNICIPALITIES FOUND:\n")
  city_summary <- results %>%
    count(city, state, sort = TRUE) %>%
    head(20)
  for (i in 1:nrow(city_summary)) {
    cat(sprintf("   • %s (%s): %d occurrences\n", city_summary$city[i], city_summary$state[i], city_summary$n[i]))
  }
  
  # Examples
  cat("\n📝 EXAMPLES BY PATTERN TYPE:\n")
  pattern_types <- unique(results$pattern_type)
  for (pattern in pattern_types) {
    examples <- results %>%
      filter(pattern_type == pattern) %>%
      head(3)
    
    if (nrow(examples) > 0) {
      cat(sprintf("\n   %s:\n", str_to_title(str_replace_all(pattern, "_", " "))))
      for (i in 1:nrow(examples)) {
        cat(sprintf("     - '%s' → %s (%s)\n", examples$original_text[i], examples$city[i], examples$state[i]))
      }
    }
  }
}

# ============================================================================
# SAVE RESULTS
# ============================================================================

save_results <- function(results) {
  if (nrow(results) == 0) return()
  
  # Save detailed results
  write_csv(results, "comprehensive_municipality_search_results.csv", na = "")
  cat(sprintf("💾 Saved %d records to comprehensive_municipality_search_results.csv\n", nrow(results)))
  
  # Create summary CSV
  summary_results <- results %>%
    group_by(city, state, pattern_type) %>%
    summarise(
      occurrences = n(),
      example_text = first(original_text),
      fields_found = paste(unique(field_name), collapse = ", "),
      .groups = 'drop'
    ) %>%
    arrange(state, city)
  
  write_csv(summary_results, "municipality_patterns_summary.csv", na = "")
  cat(sprintf("💾 Saved summary with %d unique municipalities to municipality_patterns_summary.csv\n", nrow(summary_results)))
}

# ============================================================================
# RUN ANALYSIS
# ============================================================================

cat("1️⃣ Starting comprehensive municipality search...\n")
results <- main_analysis()

cat("\n2️⃣ Generating report...\n")
generate_report(results)

cat("\n3️⃣ Saving results...\n")
save_results(results)

cat("\n✅ COMPREHENSIVE MUNICIPALITY SEARCH COMPLETED!\n")
cat("Files created:\n")
cat("  • comprehensive_municipality_search_results.csv\n")
cat("  • municipality_patterns_summary.csv\n")