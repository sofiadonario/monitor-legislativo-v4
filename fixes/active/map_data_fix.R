# Map Data Fix for Railway Production
# This file fixes the data structure issues in the maps module

# Function to clean and prepare map data
clean_map_data <- function(data) {
  if (is.null(data) || nrow(data) == 0) {
    return(data.frame(
      state = character(),
      documents = numeric(),
      stringsAsFactors = FALSE
    ))
  }
  
  # Ensure we have proper column names
  if ("estado" %in% names(data) && !"state" %in% names(data)) {
    data$state <- data$estado
  }
  
  # Clean empty strings and convert to NA
  if ("state" %in% names(data)) {
    data$state[data$state == ""] <- NA
  }
  
  # Handle municipality column
  if ("municipio" %in% names(data) && !"municipality" %in% names(data)) {
    data$municipality <- data$municipio
  }
  if ("municipality" %in% names(data)) {
    data$municipality[data$municipality == ""] <- NA
  }
  
  # Standardize state codes
  if ("state" %in% names(data)) {
    # Convert state names to codes if needed
    state_mapping <- c(
      "acre" = "AC", "alagoas" = "AL", "amapá" = "AP", "amapa" = "AP",
      "amazonas" = "AM", "bahia" = "BA", "ceará" = "CE", "ceara" = "CE",
      "distrito federal" = "DF", "espírito santo" = "ES", "espirito santo" = "ES",
      "goiás" = "GO", "goias" = "GO", "maranhão" = "MA", "maranhao" = "MA",
      "mato grosso" = "MT", "mato grosso do sul" = "MS", "minas gerais" = "MG",
      "pará" = "PA", "para" = "PA", "paraíba" = "PB", "paraiba" = "PB",
      "paraná" = "PR", "parana" = "PR", "pernambuco" = "PE", "piauí" = "PI",
      "piaui" = "PI", "rio de janeiro" = "RJ", "rio grande do norte" = "RN",
      "rio grande do sul" = "RS", "rondônia" = "RO", "rondonia" = "RO",
      "roraima" = "RR", "santa catarina" = "SC", "são paulo" = "SP",
      "sao paulo" = "SP", "sergipe" = "SE", "tocantins" = "TO"
    )
    
    # Clean and standardize
    data$state <- toupper(trimws(data$state))
    
    # Map full names to codes
    lower_states <- tolower(data$state)
    for (name in names(state_mapping)) {
      data$state[lower_states == name] <- state_mapping[name]
    }
    
    # Keep only valid 2-letter state codes
    valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
                      "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
                      "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO")
    data$state[!data$state %in% valid_states] <- NA
  }
  
  # Ensure date column exists and is proper type
  if ("data_publicacao" %in% names(data) && !"date" %in% names(data)) {
    data$date <- data$data_publicacao
  }
  if ("date" %in% names(data)) {
    data$date <- as.Date(data$date, optional = TRUE)
  }
  
  # Add year if missing
  if (!"year" %in% names(data) && "date" %in% names(data)) {
    data$year <- as.numeric(format(data$date, "%Y"))
  }
  
  # Handle document_type
  if ("tipo" %in% names(data) && !"document_type" %in% names(data)) {
    data$document_type <- data$tipo
  }
  
  # Handle category
  if ("raw_category" %in% names(data) && !"category" %in% names(data)) {
    data$category <- data$raw_category
  }
  if ("categoria_original" %in% names(data) && !"category" %in% names(data)) {
    data$category <- data$categoria_original
  }
  
  return(data)
}

# Export the function
if (!exists("clean_map_data", mode = "function")) {
  assign("clean_map_data", clean_map_data, envir = .GlobalEnv)
}