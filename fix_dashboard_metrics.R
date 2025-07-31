# Fix dashboard metrics to use documents view and handle null data properly

# Override the get_lexml_dashboard_metrics function
get_lexml_dashboard_metrics <<- function() {
  cat("📊 get_lexml_dashboard_metrics - using documents view\n")
  
  if (!exists(".db_pool") || is.null(.db_pool) || !inherits(.db_pool, "Pool")) {
    cat("⚠️ No database pool available\n")
    return(list(
      total_documents = 0,
      states_percentage = 0,
      municipalities_percentage = 0,
      date_range_years = 0,
      last_updated = Sys.time()
    ))
  }
  
  tryCatch({
    # Get total documents
    total_result <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents")
    total_documents <- if(nrow(total_result) > 0) total_result$count[1] else 0
    
    # Get state coverage
    state_result <- dbGetQuery(.db_pool, "
      SELECT COUNT(DISTINCT estado) as state_count 
      FROM documents 
      WHERE estado IS NOT NULL AND estado <> '' AND estado <> 'BR'
    ")
    states_with_docs <- if(nrow(state_result) > 0) state_result$state_count[1] else 0
    states_percentage <- round((states_with_docs / 27) * 100, 1) # Brazil has 27 states
    
    # Get municipality data - Note: most documents don't have municipality data
    mun_result <- dbGetQuery(.db_pool, "
      SELECT COUNT(DISTINCT municipality) as mun_count 
      FROM documents 
      WHERE municipality IS NOT NULL 
        AND municipality <> '' 
        AND municipality <> 'Nacional'
    ")
    municipalities_with_docs <- if(nrow(mun_result) > 0) mun_result$mun_count[1] else 0
    # Brazil has ~5,570 municipalities, but legislative docs often don't specify municipality
    municipalities_percentage <- if(municipalities_with_docs > 0) ">0" else "0"
    
    # Get date range
    date_result <- dbGetQuery(.db_pool, "
      SELECT 
        MIN(data_publicacao::date) as min_date,
        MAX(data_publicacao::date) as max_date
      FROM documents 
      WHERE data_publicacao IS NOT NULL
    ")
    
    date_range_years <- 0
    if(nrow(date_result) > 0 && !is.na(date_result$min_date[1]) && !is.na(date_result$max_date[1])) {
      min_year <- as.numeric(format(as.Date(date_result$min_date[1]), "%Y"))
      max_year <- as.numeric(format(as.Date(date_result$max_date[1]), "%Y"))
      date_range_years <- max_year - min_year + 1
    }
    
    result <- list(
      total_documents = total_documents,
      states_percentage = states_percentage,
      municipalities_percentage = municipalities_percentage,
      date_range_years = date_range_years,
      last_updated = Sys.time()
    )
    
    cat("✅ Metrics retrieved: ", total_documents, " documents, ", 
        states_percentage, "% states, ", 
        municipalities_percentage, "% municipalities\n")
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Error in get_lexml_dashboard_metrics:", e$message, "\n")
    return(list(
      total_documents = 0,
      states_percentage = 0,
      municipalities_percentage = 0,
      date_range_years = 0,
      last_updated = Sys.time()
    ))
  })
}

# Also fix get_available_states to return all Brazilian states
get_available_states <<- function() {
  cat("🗺️ get_available_states called\n")
  # Return all Brazilian states
  return(c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
           "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
           "RS", "RO", "RR", "SC", "SP", "SE", "TO"))
}

# Fix the summary function
get_lexml_update_summary <<- function() {
  cat("📋 get_lexml_update_summary called\n")
  
  if (!exists(".db_pool") || is.null(.db_pool) || !inherits(.db_pool, "Pool")) {
    return("Database not connected")
  }
  
  tryCatch({
    # Get counts by species and transport category
    summary_data <- dbGetQuery(.db_pool, "
      SELECT 
        species,
        transport_category,
        COUNT(*) as count
      FROM documents
      GROUP BY species, transport_category
      ORDER BY species, transport_category
    ")
    
    if(nrow(summary_data) > 0) {
      total <- sum(summary_data$count)
      summary_text <- paste0(
        "Total: ", format(total, big.mark = ","), " documents<br/>",
        "Species: ", paste(unique(summary_data$species), collapse = ", "), "<br/>",
        "Transport: ", paste(unique(summary_data$transport_category), collapse = ", ")
      )
      return(summary_text)
    } else {
      return("No data available")
    }
    
  }, error = function(e) {
    return(paste("Error:", e$message))
  })
}

cat("✅ Dashboard metrics functions fixed\n")