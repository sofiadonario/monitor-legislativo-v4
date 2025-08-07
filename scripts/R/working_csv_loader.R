# Working CSV Data Loader - Handles available data properly
# Addresses: DF as State, proper regions, and current parsing limitations

library(dplyr)

# Brazilian states (27 total including DF)
BRAZILIAN_STATES <- c(
  "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
  "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
  "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"
)

# Brazilian regions (correct geographic classification)
STATE_TO_REGION <- list(
  "North" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
  "Northeast" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"), 
  "Southeast" = c("ES", "MG", "RJ", "SP"),
  "South" = c("PR", "RS", "SC"),
  "West-Central" = c("DF", "GO", "MT", "MS")  # DF is West-Central region
)

# State name standardization (vectorized)
normalize_state <- function(state_vector) {
  case_when(
    is.na(state_vector) | state_vector == "" ~ NA_character_,
    grepl("São Paulo", state_vector) ~ "SP",
    grepl("Minas Gerais", state_vector) ~ "MG",
    state_vector == "Distrito Federal" ~ "DF",
    state_vector == "Rio de Janeiro" ~ "RJ",
    state_vector == "Rio Grande do Sul" ~ "RS",
    state_vector == "Santa Catarina" ~ "SC",
    state_vector == "Espírito Santo" ~ "ES",
    state_vector == "Rondônia" ~ "RO",
    state_vector == "Amazonas" ~ "AM",
    state_vector == "Alagoas" ~ "AL",
    # Handle malformed entries like "PonteNova- MG"
    grepl("- MG$", state_vector) ~ "MG",
    grepl("- SP$", state_vector) ~ "SP",
    grepl("- RJ$", state_vector) ~ "RJ",
    # If already standard abbreviation
    state_vector %in% BRAZILIAN_STATES ~ state_vector,
    TRUE ~ state_vector
  )
}

# Get region from state
get_region <- function(state_code) {
  for (region in names(STATE_TO_REGION)) {
    if (state_code %in% STATE_TO_REGION[[region]]) {
      return(region)
    }
  }
  return(NA_character_)
}

# Load CSV data with current parsing capability
load_csv_data <- function() {
  cat("🔄 Loading CSV data with working parser...\n")
  
  # Load what we can parse (1957 documents)
  data <- read.csv("./data_current/processed/Geral.csv", 
                   stringsAsFactors = FALSE,
                   fileEncoding = "UTF-8-BOM")
  
  # Clean column names  
  names(data)[1] <- gsub("^\\ufeff|^\\xef\\xbb\\xbf", "", names(data)[1])
  
  cat("📊 Loaded", nrow(data), "documents (CSV parsing limitation - actual file has ~5.7k)\n")
  
  # Process the data
  processed <- data %>%
    mutate(
      # Normalize states (DF is a STATE)
      State_clean = normalize_state(State),
      
      # Get geographic region (vectorized)
      Geographic_region = sapply(State_clean, get_region, USE.NAMES = FALSE),
      
      # Classify jurisdiction (corrected - DF is State level)
      Jurisdiction_level = case_when(
        !is.na(Municipality) & Municipality != "" ~ "Municipal",
        !is.na(State_clean) & State_clean != "" ~ "State",
        Region == "Federal" | Court_class %in% c("Legislativo Federal", "STF") ~ "Federal",
        TRUE ~ "Undefined"
      ),
      
      # For display
      Display_state = State_clean
    )
  
  return(processed)
}

# Generate dashboard statistics
get_dashboard_stats <- function(data) {
  if (is.null(data)) return(NULL)
  
  # All 27 states with counts
  state_counts <- data %>%
    filter(!is.na(Display_state)) %>%
    count(Display_state, name = "Count")
  
  all_states <- data.frame(State = BRAZILIAN_STATES) %>%
    left_join(state_counts, by = c("State" = "Display_state")) %>%
    mutate(Count = ifelse(is.na(Count), 0, Count)) %>%
    arrange(desc(Count))
  
  # Regional distribution
  region_counts <- data %>%
    filter(!is.na(Geographic_region)) %>%
    count(Geographic_region, name = "Count") %>%
    arrange(desc(Count))
  
  # Jurisdiction distribution
  jurisdiction_counts <- data %>%
    count(Jurisdiction_level, name = "Count") %>%
    arrange(desc(Count))
  
  # Document types
  type_counts <- data %>%
    count(Urn_type, name = "Count") %>%
    arrange(desc(Count))
  
  return(list(
    total_documents = nrow(data),
    by_state = all_states,
    by_region = region_counts,
    by_jurisdiction = jurisdiction_counts, 
    by_type = type_counts,
    states_with_data = nrow(filter(all_states, Count > 0)),
    note = "Data from successfully parsed portion of CSV (parsing issue limits to ~1957 of ~5763 documents)"
  ))
}

# Get data for maps with proper layers
get_map_layers <- function(data, doc_type = NULL) {
  if (is.null(data)) return(NULL)
  
  # Filter by document type if specified
  if (!is.null(doc_type)) {
    data <- filter(data, Urn_type == doc_type)
  }
  
  # Create jurisdiction layers
  layers <- list(
    federal = filter(data, Jurisdiction_level == "Federal"),
    state = filter(data, Jurisdiction_level == "State", !is.na(Display_state)),
    municipal = filter(data, Jurisdiction_level == "Municipal", !is.na(Display_state))
  )
  
  # Add region breakdown for state-level documents
  if (nrow(layers$state) > 0) {
    layers$by_region <- layers$state %>%
      filter(!is.na(Geographic_region)) %>%
      count(Geographic_region, Display_state, name = "Count") %>%
      arrange(Geographic_region, desc(Count))
  }
  
  return(layers)
}

# Initialize all data
initialize_working_csv_data <- function() {
  cat("🔄 Initializing working CSV data loader...\n")
  cat("⚠️ Note: CSV file has parsing issues limiting to ~1957 of ~5763 documents\n")
  cat("📋 Corrections applied:\n")
  cat("   • DF treated as STATE (West-Central region)\n") 
  cat("   • Regions: North, Northeast, Southeast, South, West-Central\n")
  cat("   • Proper state normalization\n")
  
  # Load data
  csv_data <<- load_csv_data()
  
  if (!is.null(csv_data)) {
    # Generate dashboard statistics
    dashboard_stats <<- get_dashboard_stats(csv_data)
    
    cat("📊 Dashboard Statistics:\n")
    cat("   Total documents:", dashboard_stats$total_documents, "\n")
    cat("   States with data:", dashboard_stats$states_with_data, "/27\n")
    
    if (nrow(dashboard_stats$by_region) > 0) {
      cat("   Regional distribution:\n")
      for (i in 1:nrow(dashboard_stats$by_region)) {
        cat("     ", dashboard_stats$by_region$Geographic_region[i], ":", 
            dashboard_stats$by_region$Count[i], "documents\n")
      }
    }
    
    # Create map layers for different document types
    legislation_layers <<- get_map_layers(csv_data, "legislation")
    jurisprudence_layers <<- get_map_layers(csv_data, "jurisprudence")
    
    cat("📊 Legislation documents: Federal =", nrow(legislation_layers$federal),
        ", State =", nrow(legislation_layers$state),
        ", Municipal =", nrow(legislation_layers$municipal), "\n")
    
    cat("📊 Jurisprudence documents: Federal =", nrow(jurisprudence_layers$federal),
        ", State =", nrow(jurisprudence_layers$state),
        ", Municipal =", nrow(jurisprudence_layers$municipal), "\n")
    
    cat("✅ Working CSV data initialization complete\n")
    cat("🔧 TODO: Fix CSV parsing to access all ~5763 documents\n")
    
    return(TRUE)
  } else {
    cat("❌ Failed to load CSV data\n")
    return(FALSE)
  }
}

cat("📋 Working CSV Data Loader ready\n")