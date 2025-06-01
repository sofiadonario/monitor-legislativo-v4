# Fixed CSV Data Loader for ./data_current files
# Corrected for: DF as State, Geographic Regions, Full document count

library(dplyr)
library(readr)
library(purrr)

# Brazilian states list for complete coverage display (27 states including DF)
BRAZILIAN_STATES <- c(
  "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
  "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
  "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"
)

# Brazilian regions mapping (correct geographic regions)
STATE_TO_REGION <- list(
  "North" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
  "Northeast" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"), 
  "Southeast" = c("ES", "MG", "RJ", "SP"),
  "South" = c("PR", "RS", "SC"),
  "West-Central" = c("DF", "GO", "MT", "MS")
)

# State name normalization mapping
STATE_MAPPING <- c(
  "São Paulo" = "SP",
  "Minas Gerais" = "MG", 
  "Rio de Janeiro" = "RJ",
  "Rio Grande do Sul" = "RS",
  "Santa Catarina" = "SC",
  "Espírito Santo" = "ES",
  "Rondônia" = "RO",
  "Amazonas" = "AM",
  "Alagoas" = "AL",
  "Distrito Federal" = "DF"
)

# Function to get region from state
get_region_from_state <- function(state_code) {
  for (region in names(STATE_TO_REGION)) {
    if (state_code %in% STATE_TO_REGION[[region]]) {
      return(region)
    }
  }
  return(NA_character_)
}

# Function to classify jurisdiction levels (CORRECTED)
classify_jurisdiction <- function(data) {
  data %>%
    mutate(
      # Normalize state names
      State_normalized = case_when(
        State %in% names(STATE_MAPPING) ~ STATE_MAPPING[State],
        State %in% BRAZILIAN_STATES ~ State,
        TRUE ~ State
      ),
      
      # DF is a STATE, not regional
      State_normalized = ifelse(Region == "Distrital", "DF", State_normalized),
      
      # Classify jurisdiction level (FIXED)
      Jurisdiction_level = case_when(
        !is.na(Municipality) & Municipality != "" ~ "Municipal",
        !is.na(State_normalized) & State_normalized != "" ~ "State",
        Region == "Federal" | Court_class == "Legislativo Federal" | Court_class == "STF" ~ "Federal",
        TRUE ~ "Undefined"
      ),
      
      # Geographic region (North, Northeast, Southeast, South, West-Central)
      Geographic_region = case_when(
        !is.na(State_normalized) ~ get_region_from_state(State_normalized),
        TRUE ~ NA_character_
      ),
      
      # Display state (use normalized)
      Display_state = State_normalized
    )
}

# Load and process Geral.csv for document overview (FIXED)
load_geral_data <- function() {
  file_path <- "./data_current/processed/Geral.csv"
  
  if (!file.exists(file_path)) {
    cat("❌ Geral.csv not found at", file_path, "\n")
    return(NULL)
  }
  
  tryCatch({
    # Fix BOM and encoding issues
    data <- read_csv(file_path, 
                     locale = locale(encoding = "UTF-8"), 
                     show_col_types = FALSE,
                     skip_empty_rows = TRUE)
    
    # Remove BOM from first column name if present
    colnames(data)[1] <- gsub("^\\ufeff", "", colnames(data)[1])
    
    cat("📊 Loaded", nrow(data), "records from Geral.csv (should be ~5,763)\n")
    
    # Process and classify jurisdictions
    processed_data <- classify_jurisdiction(data)
    
    return(processed_data)
  }, error = function(e) {
    cat("❌ Error loading Geral.csv:", e$message, "\n")
    return(NULL)
  })
}

# Load and process Legislação___Geral.csv for legislative documents map
load_legislation_data <- function() {
  file_path <- "./data_current/processed/Legislação___Geral.csv"
  
  if (!file.exists(file_path)) {
    cat("❌ Legislação___Geral.csv not found at", file_path, "\n")
    return(NULL)
  }
  
  tryCatch({
    data <- read_csv(file_path, 
                     locale = locale(encoding = "UTF-8"), 
                     show_col_types = FALSE,
                     skip_empty_rows = TRUE)
    
    # Remove BOM from first column name if present  
    colnames(data)[1] <- gsub("^\\ufeff", "", colnames(data)[1])
    
    cat("📊 Loaded", nrow(data), "legislative records\n")
    
    # Process and classify jurisdictions
    processed_data <- classify_jurisdiction(data) %>%
      filter(Urn_type == "legislation") # Ensure only legislation documents
    
    return(processed_data)
  }, error = function(e) {
    cat("❌ Error loading Legislação___Geral.csv:", e$message, "\n")
    return(NULL)
  })
}

# Load and process Jurisprudência___Geral.csv for jurisprudence documents map
load_jurisprudence_data <- function() {
  file_path <- "./data_current/processed/Jurisprudência___Geral.csv"
  
  if (!file.exists(file_path)) {
    cat("❌ Jurisprudência___Geral.csv not found at", file_path, "\n")
    return(NULL)
  }
  
  tryCatch({
    data <- read_csv(file_path, 
                     locale = locale(encoding = "UTF-8"), 
                     show_col_types = FALSE,
                     skip_empty_rows = TRUE)
    
    # Remove BOM from first column name if present
    colnames(data)[1] <- gsub("^\\ufeff", "", colnames(data)[1])
    
    cat("📊 Loaded", nrow(data), "jurisprudence records\n")
    
    # Process and classify jurisdictions
    processed_data <- classify_jurisdiction(data) %>%
      filter(Urn_type == "jurisprudence") # Ensure only jurisprudence documents
    
    return(processed_data)
  }, error = function(e) {
    cat("❌ Error loading Jurisprudência___Geral.csv:", e$message, "\n")
    return(NULL)
  })
}

# Generate document overview statistics showing all 27 states (CORRECTED)
get_document_overview_stats <- function(geral_data = NULL) {
  if (is.null(geral_data)) {
    geral_data <- load_geral_data()
  }
  
  if (is.null(geral_data)) {
    return(list(
      total_documents = 0,
      by_state = data.frame(State = BRAZILIAN_STATES, Count = 0, stringsAsFactors = FALSE),
      by_jurisdiction = data.frame(),
      by_document_type = data.frame(),
      by_region = data.frame()
    ))
  }
  
  # Count by state (ensure all 27 states are represented)
  state_counts <- geral_data %>%
    filter(!is.na(Display_state) & Display_state != "") %>%
    count(Display_state, name = "Count") %>%
    rename(State = Display_state)
  
  # Create complete state list with counts
  all_states_counts <- data.frame(State = BRAZILIAN_STATES, stringsAsFactors = FALSE) %>%
    left_join(state_counts, by = "State") %>%
    mutate(Count = ifelse(is.na(Count), 0, Count)) %>%
    arrange(desc(Count))
  
  # Count by jurisdiction level
  jurisdiction_counts <- geral_data %>%
    count(Jurisdiction_level, name = "Count") %>%
    arrange(desc(Count))
  
  # Count by document type
  document_type_counts <- geral_data %>%
    count(Urn_type, name = "Count") %>%
    arrange(desc(Count))
  
  # Count by geographic region (ADDED)
  region_counts <- geral_data %>%
    filter(!is.na(Geographic_region)) %>%
    count(Geographic_region, name = "Count") %>%
    arrange(desc(Count))
  
  return(list(
    total_documents = nrow(geral_data),
    by_state = all_states_counts,
    by_jurisdiction = jurisdiction_counts,
    by_document_type = document_type_counts,
    by_region = region_counts,
    coverage_summary = list(
      states_with_documents = nrow(filter(all_states_counts, Count > 0)),
      total_states = 27,
      federal_documents = nrow(filter(geral_data, Jurisdiction_level == "Federal")),
      state_documents = nrow(filter(geral_data, Jurisdiction_level == "State")),
      municipal_documents = nrow(filter(geral_data, Jurisdiction_level == "Municipal"))
    )
  ))
}

# Get jurisdiction layer data for maps (UPDATED)
get_jurisdiction_layers <- function(data) {
  if (is.null(data)) {
    return(list())
  }
  
  # Filter out undefined jurisdiction documents for mapping
  mappable_data <- data %>%
    filter(Jurisdiction_level != "Undefined" & !is.na(Display_state))
  
  layers <- list(
    federal = filter(mappable_data, Jurisdiction_level == "Federal"),
    state = filter(mappable_data, Jurisdiction_level == "State"),
    municipal = filter(mappable_data, Jurisdiction_level == "Municipal")
  )
  
  # Add summary stats for each layer with regions
  layer_stats <- map(layers, function(layer) {
    region_stats <- layer %>% 
      filter(!is.na(Geographic_region)) %>%
      count(Geographic_region) %>%
      arrange(desc(n))
    
    list(
      count = nrow(layer),
      states = length(unique(layer$Display_state[!is.na(layer$Display_state)])),
      regions = region_stats,
      document_types = layer %>% count(Document_type_full) %>% arrange(desc(n))
    )
  })
  
  return(list(
    data = layers,
    stats = layer_stats
  ))
}

# Initialize CSV data loading (UPDATED)
initialize_csv_data <- function() {
  cat("🔄 Initializing CORRECTED CSV data loading from ./data_current/processed/\n")
  
  # Load all datasets
  geral_data <<- load_geral_data()
  legislation_data <<- load_legislation_data()
  jurisprudence_data <<- load_jurisprudence_data()
  
  # Generate overview statistics
  if (!is.null(geral_data)) {
    document_overview_stats <<- get_document_overview_stats(geral_data)
    cat("📊 Document overview: Total =", document_overview_stats$total_documents, 
        "documents, States with documents =", document_overview_stats$coverage_summary$states_with_documents, "/27\n")
    
    # Print region breakdown
    if (nrow(document_overview_stats$by_region) > 0) {
      cat("🗺️ Documents by region:\n")
      for (i in 1:nrow(document_overview_stats$by_region)) {
        cat("   ", document_overview_stats$by_region$Geographic_region[i], ":", 
            document_overview_stats$by_region$Count[i], "documents\n")
      }
    }
  }
  
  # Generate jurisdiction layers for maps
  if (!is.null(legislation_data)) {
    legislation_layers <<- get_jurisdiction_layers(legislation_data)
    cat("📊 Legislative documents by jurisdiction: Federal =", legislation_layers$stats$federal$count,
        ", State =", legislation_layers$stats$state$count,
        ", Municipal =", legislation_layers$stats$municipal$count, "\n")
  }
  
  if (!is.null(jurisprudence_data)) {
    jurisprudence_layers <<- get_jurisdiction_layers(jurisprudence_data)
    cat("📊 Jurisprudence documents by jurisdiction: Federal =", jurisprudence_layers$stats$federal$count,
        ", State =", jurisprudence_layers$stats$state$count,
        ", Municipal =", jurisprudence_layers$stats$municipal$count, "\n")
  }
  
  cat("✅ CORRECTED CSV data loading initialization complete\n")
  return(TRUE)
}

cat("📋 CORRECTED CSV Data Loader for ./data_current loaded successfully\n")
cat("   - DF treated as STATE (not regional)\n")
cat("   - Regions: North, Northeast, Southeast, South, West-Central\n")
cat("   - Fixed BOM encoding issues for full document count\n")