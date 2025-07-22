# Final CSV Data Loader - Federal→State→Municipal Structure
# Using recovered CSV data (2,300+ documents from 5.7k original)

library(dplyr)
library(readr)
library(purrr)

# Brazilian states (27 total)
BRAZILIAN_STATES <- c(
  "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
  "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
  "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"
)

# State name normalization
normalize_state_name <- function(state_vector) {
  case_when(
    is.na(state_vector) | state_vector == "" ~ NA_character_,
    grepl("São Paulo", state_vector, ignore.case = TRUE) ~ "SP",
    grepl("Minas Gerais", state_vector, ignore.case = TRUE) ~ "MG",
    state_vector == "Distrito Federal" ~ "DF",
    grepl("Rio de Janeiro", state_vector, ignore.case = TRUE) ~ "RJ",
    grepl("Rio Grande do Sul", state_vector, ignore.case = TRUE) ~ "RS",
    grepl("Santa Catarina", state_vector, ignore.case = TRUE) ~ "SC",
    grepl("Espírito Santo", state_vector, ignore.case = TRUE) ~ "ES",
    grepl("Rondônia", state_vector, ignore.case = TRUE) ~ "RO",
    grepl("Amazonas", state_vector, ignore.case = TRUE) ~ "AM",
    grepl("Alagoas", state_vector, ignore.case = TRUE) ~ "AL",
    # Handle malformed entries
    grepl("- MG$", state_vector) ~ "MG",
    grepl("- SP$", state_vector) ~ "SP",
    grepl("- RJ$", state_vector) ~ "RJ",
    # If already standard abbreviation
    state_vector %in% BRAZILIAN_STATES ~ state_vector,
    TRUE ~ state_vector
  )
}

# CORRECT Jurisdiction Classification: Federal → State → Municipal
classify_jurisdiction_correct <- function(data) {
  data %>%
    mutate(
      # Normalize state names
      State_clean = normalize_state_name(State),
      
      # CORRECT Federal → State → Municipal hierarchy
      Jurisdiction_level = case_when(
        # FEDERAL: All legislative results start here
        Region == "Federal" | 
        Court_class %in% c("Legislativo Federal", "STF") |
        grepl("Federal|Congresso Nacional|Supremo", Justice, ignore.case = TRUE) |
        grepl("federal", Court_class, ignore.case = TRUE) ~ "Federal",
        
        # MUNICIPAL: If has Municipality, it's municipal level  
        !is.na(Municipality) & Municipality != "" ~ "Municipal",
        
        # STATE: If has State but not Federal or Municipal
        !is.na(State_clean) & State_clean != "" ~ "State",
        
        TRUE ~ "Undefined"
      ),
      
      # Display state for mapping
      Display_state = State_clean
    )
}

# Load working CSV files
load_working_geral <- function() {
  file_path <- "./data_current/processed/Geral_working.csv"
  
  if (!file.exists(file_path)) {
    cat("❌ Geral_working.csv not found\n")
    return(NULL)
  }
  
  tryCatch({
    data <- read_csv(file_path, locale = locale(encoding = "UTF-8"), show_col_types = FALSE)
    cat("📊 Loaded", nrow(data), "documents from recovered Geral data\n")
    
    # Apply correct jurisdiction classification
    processed <- classify_jurisdiction_correct(data)
    
    # Show jurisdiction breakdown
    jurisdiction_summary <- processed %>% 
      count(Jurisdiction_level) %>%
      arrange(desc(n))
    
    cat("⚖️  Jurisdiction breakdown:\n")
    for (i in 1:nrow(jurisdiction_summary)) {
      cat("   ", jurisdiction_summary$Jurisdiction_level[i], ":", jurisdiction_summary$n[i], "documents\n")
    }
    
    return(processed)
  }, error = function(e) {
    cat("❌ Error loading Geral_working.csv:", e$message, "\n")
    return(NULL)
  })
}

load_working_legislation <- function() {
  file_path <- "./data_current/processed/Legislação___Geral_working.csv"
  
  if (!file.exists(file_path)) {
    cat("❌ Legislação___Geral_working.csv not found\n")
    return(NULL)
  }
  
  tryCatch({
    data <- read_csv(file_path, locale = locale(encoding = "UTF-8"), show_col_types = FALSE)
    cat("📊 Loaded", nrow(data), "legislative documents from recovered data\n")
    
    processed <- classify_jurisdiction_correct(data) %>%
      filter(Urn_type == "legislation")
    
    return(processed)
  }, error = function(e) {
    cat("❌ Error loading Legislação___Geral_working.csv:", e$message, "\n")
    return(NULL)
  })
}

load_working_jurisprudence <- function() {
  file_path <- "./data_current/processed/Jurisprudência___Geral_working.csv"
  
  if (!file.exists(file_path)) {
    cat("❌ Jurisprudência___Geral_working.csv not found\n") 
    return(NULL)
  }
  
  tryCatch({
    data <- read_csv(file_path, locale = locale(encoding = "UTF-8"), show_col_types = FALSE)
    cat("📊 Loaded", nrow(data), "jurisprudence documents from recovered data\n")
    
    processed <- classify_jurisdiction_correct(data) %>%
      filter(Urn_type == "jurisprudence")
    
    return(processed)
  }, error = function(e) {
    cat("❌ Error loading Jurisprudência___Geral_working.csv:", e$message, "\n")
    return(NULL)
  })
}

# Generate dashboard statistics with ALL 27 states
get_final_dashboard_stats <- function(geral_data) {
  if (is.null(geral_data)) return(NULL)
  
  # Count by state - show ALL 27 states
  state_counts <- geral_data %>%
    filter(!is.na(Display_state)) %>%
    count(Display_state, name = "Count")
  
  all_states_counts <- data.frame(State = BRAZILIAN_STATES) %>%
    left_join(state_counts, by = c("State" = "Display_state")) %>%
    mutate(Count = ifelse(is.na(Count), 0, Count)) %>%
    arrange(desc(Count))
  
  # Jurisdiction distribution
  jurisdiction_counts <- geral_data %>%
    count(Jurisdiction_level, name = "Count") %>%
    arrange(desc(Count))
  
  # Document type distribution
  type_counts <- geral_data %>%
    count(Urn_type, name = "Count") %>%
    arrange(desc(Count))
  
  return(list(
    total_documents = nrow(geral_data),
    by_state = all_states_counts,
    by_jurisdiction = jurisdiction_counts,
    by_type = type_counts,
    states_with_data = nrow(filter(all_states_counts, Count > 0)),
    note = "Recovered from corrupted CSV files - originally ~5.7k documents"
  ))
}

# Create map layers for interactive maps
get_final_map_layers <- function(data, filter_type = NULL) {
  if (is.null(data)) return(NULL)
  
  # Filter by document type if specified
  if (!is.null(filter_type)) {
    data <- filter(data, Urn_type == filter_type)
  }
  
  # Create jurisdiction layers for maps
  layers <- list(
    federal = filter(data, Jurisdiction_level == "Federal"),
    state = filter(data, Jurisdiction_level == "State", !is.na(Display_state)),  
    municipal = filter(data, Jurisdiction_level == "Municipal", !is.na(Display_state))
  )
  
  # Add counts for each layer
  layer_stats <- list(
    federal_count = nrow(layers$federal),
    state_count = nrow(layers$state),
    municipal_count = nrow(layers$municipal),
    state_distribution = layers$state %>% count(Display_state) %>% arrange(desc(n)),
    municipal_distribution = layers$municipal %>% count(Display_state, Municipality) %>% arrange(desc(n))
  )
  
  return(list(
    data = layers,
    stats = layer_stats
  ))
}

# Initialize final CSV data system
initialize_final_csv_data <- function() {
  cat("🔄 Initializing FINAL CSV data system\n")
  cat("   Using recovered data from CSV corruption fix\n")
  cat("   Implementing correct Federal → State → Municipal structure\n\n")
  
  # Load all working datasets
  final_geral_data <<- load_working_geral()
  final_legislation_data <<- load_working_legislation()
  final_jurisprudence_data <<- load_working_jurisprudence()
  
  if (!is.null(final_geral_data)) {
    # Generate dashboard statistics
    final_dashboard_stats <<- get_final_dashboard_stats(final_geral_data)
    
    cat("📊 FINAL Dashboard Statistics:\n")
    cat("   Total documents:", final_dashboard_stats$total_documents, "\n")
    cat("   States with data:", final_dashboard_stats$states_with_data, "/27\n")
    
    if (nrow(final_dashboard_stats$by_jurisdiction) > 0) {
      cat("   Jurisdiction distribution:\n")
      for (i in 1:nrow(final_dashboard_stats$by_jurisdiction)) {
        cat("     ", final_dashboard_stats$by_jurisdiction$Jurisdiction_level[i], ":", 
            final_dashboard_stats$by_jurisdiction$Count[i], "documents\n")
      }
    }
    
    # Create map layers for different document types
    final_legislation_layers <<- get_final_map_layers(final_legislation_data, "legislation")
    final_jurisprudence_layers <<- get_final_map_layers(final_jurisprudence_data, "jurisprudence")
    
    if (!is.null(final_legislation_layers)) {
      cat("📊 Legislative map layers: Federal =", final_legislation_layers$stats$federal_count,
          ", State =", final_legislation_layers$stats$state_count,
          ", Municipal =", final_legislation_layers$stats$municipal_count, "\n")
    }
    
    if (!is.null(final_jurisprudence_layers)) {
      cat("📊 Jurisprudence map layers: Federal =", final_jurisprudence_layers$stats$federal_count,
          ", State =", final_jurisprudence_layers$stats$state_count,
          ", Municipal =", final_jurisprudence_layers$stats$municipal_count, "\n")
    }
    
    cat("✅ Final CSV data initialization complete\n")
    cat("🎯 Ready for dashboard integration with", final_dashboard_stats$total_documents, "documents\n")
    
    return(TRUE)
  } else {
    cat("❌ Failed to load final CSV data\n")
    return(FALSE)
  }
}

cat("📋 Final CSV Data Loader ready - Federal→State→Municipal structure\n")