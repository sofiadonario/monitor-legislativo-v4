#!/usr/bin/env Rscript
# Fix LexML data issues
# Addresses state code problems, data quality, and display issues

cat("=== Fixing LexML Data Issues ===\n")

# Load required libraries (if available)
tryCatch({
  library(dplyr)
  library(readr)
  library(jsonlite)
}, error = function(e) {
  cat("⚠️ Some packages not available, using base R functions\n")
})

# Function to read CSV with base R
read_csv_base <- function(file_path) {
  lines <- readLines(file_path)
  # Parse header
  header <- strsplit(lines[1], ",")[[1]]
  
  # Parse data rows
  data <- list()
  for (i in 2:length(lines)) {
    if (nchar(lines[i]) > 0) {
      row <- strsplit(lines[i], ",")[[1]]
      if (length(row) >= length(header)) {
        data[[i-1]] <- row[1:length(header)]
      }
    }
  }
  
  # Convert to data frame
  df <- do.call(rbind, data)
  colnames(df) <- header
  return(as.data.frame(df, stringsAsFactors = FALSE))
}

# Function to clean and fix state codes
clean_state_codes <- function(state_col) {
  # Brazilian state codes
  valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
                    "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
                    "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO")
  
  # Clean and standardize state codes
  cleaned <- sapply(state_col, function(x) {
    if (is.na(x) || x == "" || nchar(x) != 2) {
      return("")
    }
    x_upper <- toupper(x)
    if (x_upper %in% valid_states) {
      return(x_upper)
    } else {
      return("")
    }
  })
  
  return(cleaned)
}

# Function to extract state from other fields
extract_state_from_content <- function(title, description, summary) {
  # Brazilian state names and abbreviations
  state_patterns <- list(
    "AC" = c("acre", "ac"),
    "AL" = c("alagoas", "al"),
    "AP" = c("amapá", "amapa", "ap"),
    "AM" = c("amazonas", "am"),
    "BA" = c("bahia", "ba"),
    "CE" = c("ceará", "ceara", "ce"),
    "DF" = c("distrito federal", "df"),
    "ES" = c("espírito santo", "espirito santo", "es"),
    "GO" = c("goiás", "goias", "go"),
    "MA" = c("maranhão", "maranhao", "ma"),
    "MT" = c("mato grosso", "mt"),
    "MS" = c("mato grosso do sul", "ms"),
    "MG" = c("minas gerais", "mg"),
    "PA" = c("pará", "para", "pa"),
    "PB" = c("paraíba", "paraiba", "pb"),
    "PR" = c("paraná", "parana", "pr"),
    "PE" = c("pernambuco", "pe"),
    "PI" = c("piauí", "piaui", "pi"),
    "RJ" = c("rio de janeiro", "rj"),
    "RN" = c("rio grande do norte", "rn"),
    "RS" = c("rio grande do sul", "rs"),
    "RO" = c("rondônia", "rondonia", "ro"),
    "RR" = c("roraima", "rr"),
    "SC" = c("santa catarina", "sc"),
    "SP" = c("são paulo", "sao paulo", "sp"),
    "SE" = c("sergipe", "se"),
    "TO" = c("tocantins", "to")
  )
  
  # Combine all text for search
  combined_text <- paste(tolower(title), tolower(description), tolower(summary), collapse = " ")
  
  # Search for state patterns
  for (state_code in names(state_patterns)) {
    for (pattern in state_patterns[[state_code]]) {
      if (grepl(pattern, combined_text, ignore.case = TRUE)) {
        return(state_code)
      }
    }
  }
  
  return("")
}

# Main analysis function
analyze_and_fix_lexml_data <- function() {
  cat("🔄 Loading LexML data...\n")
  
  csv_path <- "data_current/processed/lexml_latest_results.csv"
  
  if (!file.exists(csv_path)) {
    cat("❌ LexML CSV file not found:", csv_path, "\n")
    return(NULL)
  }
  
  # Read data
  tryCatch({
    if (require(readr, quietly = TRUE)) {
      data <- read_csv(csv_path)
    } else {
      data <- read_csv_base(csv_path)
    }
    
    cat("✅ Loaded", nrow(data), "documents\n")
    
    # Analyze current state of data
    cat("\n📊 Data Analysis:\n")
    cat("- Total documents:", nrow(data), "\n")
    cat("- Columns:", paste(colnames(data), collapse = ", "), "\n")
    
    # Check state field
    if ("state" %in% colnames(data)) {
      state_data <- data$state
      empty_states <- sum(is.na(state_data) | state_data == "" | nchar(state_data) != 2)
      cat("- Empty/invalid state codes:", empty_states, "(", round(empty_states/nrow(data)*100, 1), "%)\n")
      
      # Show some examples of state data
      cat("- Sample state values:\n")
      sample_states <- head(unique(state_data[!is.na(state_data) & state_data != ""]), 10)
      for (state in sample_states) {
        cat("  '", state, "' (length: ", nchar(state), ")\n", sep = "")
      }
    }
    
    # Check document types
    if ("urn_type" %in% colnames(data)) {
      type_counts <- table(data$urn_type)
      cat("\n- Document types:\n")
      for (type in names(type_counts)) {
        cat("  ", type, ": ", type_counts[type], "\n", sep = "")
      }
    }
    
    # Check date field
    if ("enacting_date" %in% colnames(data)) {
      date_data <- data$enacting_date
      valid_dates <- sum(!is.na(date_data) & date_data != "")
      cat("- Valid dates:", valid_dates, "(", round(valid_dates/nrow(data)*100, 1), "%)\n")
    }
    
    # Check title field
    if ("title" %in% colnames(data)) {
      title_data <- data$title
      valid_titles <- sum(!is.na(title_data) & title_data != "")
      cat("- Valid titles:", valid_titles, "(", round(valid_titles/nrow(data)*100, 1), "%)\n")
    }
    
    # Check URN field
    if ("urn" %in% colnames(data)) {
      urn_data <- data$urn
      valid_urns <- sum(!is.na(urn_data) & urn_data != "" & grepl("^urn:lex:", urn_data))
      cat("- Valid URNs:", valid_urns, "(", round(valid_urns/nrow(data)*100, 1), "%)\n")
    }
    
    # Create enhanced data with fixed state codes
    cat("\n🔄 Creating enhanced dataset...\n")
    
    enhanced_data <- data
    
    # Fix state codes
    if ("state" %in% colnames(enhanced_data)) {
      cat("- Fixing state codes...\n")
      
      # First, try to clean existing state codes
      enhanced_data$estado_original <- enhanced_data$state
      enhanced_data$estado <- clean_state_codes(enhanced_data$state)
      
      # For empty state codes, try to extract from content
      empty_state_indices <- which(enhanced_data$estado == "")
      cat("- Attempting to extract state from content for", length(empty_state_indices), "documents...\n")
      
      for (i in empty_state_indices) {
        title <- ifelse("title" %in% colnames(enhanced_data), enhanced_data$title[i], "")
        description <- ifelse("document_description" %in% colnames(enhanced_data), enhanced_data$document_description[i], "")
        summary <- ifelse("document_summary" %in% colnames(enhanced_data), enhanced_data$document_summary[i], "")
        
        extracted_state <- extract_state_from_content(title, description, summary)
        if (extracted_state != "") {
          enhanced_data$estado[i] <- extracted_state
        }
      }
      
      # Count fixed state codes
      fixed_states <- sum(enhanced_data$estado != "")
      cat("- Fixed state codes:", fixed_states, "(", round(fixed_states/nrow(enhanced_data)*100, 1), "%)\n")
    }
    
    # Add transport categories
    cat("- Adding transport categories...\n")
    enhanced_data$transport_category <- sapply(enhanced_data$search_term, function(term) {
      term_lower <- tolower(term)
      if (grepl("combustível|energia|diesel|gasolina|etanol|gnv|hidrogênio", term_lower)) return("combustiveis_energia")
      if (grepl("transporte|logística|carga|caminhão|navio|trem", term_lower)) return("transporte_geral")
      if (grepl("tecnologia|inovacao|elétrico|autônomo", term_lower)) return("tecnologia_inovacao")
      if (grepl("infraestrutura|rodovia|porto|ferrovia", term_lower)) return("infraestrutura")
      if (grepl("regulamentação|norma|padrão", term_lower)) return("regulamentacao_normas")
      if (grepl("incentivo|tributação|imposto|subsídio", term_lower)) return("incentivos_tributacao")
      if (grepl("programa|política|governo", term_lower)) return("programas_governamentais")
      if (grepl("máquina|equipamento|veículo", term_lower)) return("maquinas_equipamentos")
      if (grepl("operação|serviço|manutenção", term_lower)) return("operacoes_servicos")
      return("outros")
    })
    
    # Add decade information
    cat("- Adding temporal analysis...\n")
    enhanced_data$decada <- sapply(enhanced_data$enacting_date, function(date_str) {
      if (is.na(date_str) || date_str == "") return("")
      tryCatch({
        if (grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", date_str)) {
          year <- as.numeric(substr(date_str, 1, 4))
        } else if (grepl("^[0-9]{2}/[0-9]{2}/[0-9]{4}$", date_str)) {
          year <- as.numeric(substr(date_str, 7, 10))
        } else {
          return("")
        }
        if (year >= 1800 && year <= 2030) {
          return(paste0(substr(as.character(year), 1, 3), "0s"))
        }
        return("")
      }, error = function(e) return(""))
    })
    
    # Add source identifier
    enhanced_data$fonte <- "LexML"
    
    # Save enhanced data
    output_path <- "data_current/processed/lexml_enhanced_results.csv"
    cat("- Saving enhanced data to:", output_path, "\n")
    
    if (require(readr, quietly = TRUE)) {
      write_csv(enhanced_data, output_path)
    } else {
      write.csv(enhanced_data, output_path, row.names = FALSE)
    }
    
    # Create summary statistics
    cat("\n📊 Enhanced Data Summary:\n")
    cat("- Total documents:", nrow(enhanced_data), "\n")
    
    if ("estado" %in% colnames(enhanced_data)) {
      state_counts <- table(enhanced_data$estado)
      state_counts <- state_counts[state_counts > 0]
      cat("- States with documents:", length(state_counts), "\n")
      cat("- Top 5 states:\n")
      top_states <- head(sort(state_counts, decreasing = TRUE), 5)
      for (state in names(top_states)) {
        cat("  ", state, ": ", top_states[state], "\n", sep = "")
      }
    }
    
    if ("transport_category" %in% colnames(enhanced_data)) {
      category_counts <- table(enhanced_data$transport_category)
      cat("- Transport categories:\n")
      for (category in names(category_counts)) {
        cat("  ", category, ": ", category_counts[category], "\n", sep = "")
      }
    }
    
    if ("decada" %in% colnames(enhanced_data)) {
      decade_counts <- table(enhanced_data$decada)
      decade_counts <- decade_counts[decade_counts > 0]
      cat("- Decades with documents:", length(decade_counts), "\n")
      cat("- Top 5 decades:\n")
      top_decades <- head(sort(decade_counts, decreasing = TRUE), 5)
      for (decade in names(top_decades)) {
        cat("  ", decade, ": ", top_decades[decade], "\n", sep = "")
      }
    }
    
    cat("\n✅ Enhanced LexML data created successfully!\n")
    return(enhanced_data)
    
  }, error = function(e) {
    cat("❌ Error processing LexML data:", e$message, "\n")
    return(NULL)
  })
}

# Run the analysis
result <- analyze_and_fix_lexml_data()

if (!is.null(result)) {
  cat("\n=== Fix Summary ===\n")
  cat("✅ Data quality issues identified and addressed\n")
  cat("✅ State codes cleaned and enhanced\n")
  cat("✅ Transport categories added\n")
  cat("✅ Temporal analysis added\n")
  cat("✅ Enhanced dataset saved\n")
} else {
  cat("\n❌ Failed to process LexML data\n")
}

cat("=== Fix Complete ===\n") 