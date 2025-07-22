# LexML Geographic Analytics Module
# Provides geographic aggregation and analytics for the new lexml_documents table

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)
library(sf)

# Brazilian state to region mapping
BRAZIL_REGIONS <- list(
  "North" = c("Acre", "Amazonas", "Amapá", "Pará", "Rondônia", "Roraima", "Tocantins"),
  "Northeast" = c("Alagoas", "Bahia", "Ceará", "Maranhão", "Paraíba", "Pernambuco", "Piauí", "Rio Grande do Norte", "Sergipe"),
  "Southeast" = c("Espírito Santo", "Minas Gerais", "Rio de Janeiro", "São Paulo"),
  "South" = c("Paraná", "Rio Grande do Sul", "Santa Catarina"),
  "Central-West" = c("Goiás", "Mato Grosso", "Mato Grosso do Sul", "Distrito Federal")
)

# State abbreviation mapping
STATE_ABBREV <- list(
  "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas", "BA" = "Bahia",
  "CE" = "Ceará", "DF" = "Distrito Federal", "ES" = "Espírito Santo", "GO" = "Goiás",
  "MA" = "Maranhão", "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul", "MG" = "Minas Gerais",
  "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná", "PE" = "Pernambuco", "PI" = "Piauí",
  "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte", "RS" = "Rio Grande do Sul",
  "RO" = "Rondônia", "RR" = "Roraima", "SC" = "Santa Catarina", "SP" = "São Paulo",
  "SE" = "Sergipe", "TO" = "Tocantins"
)

#' Get main dashboard metrics from lexml_documents table
#' @param db_pool Database connection pool
#' @return List with total documents, states %, municipalities %, date range
get_lexml_dashboard_metrics <- function(db_pool = NULL) {
  if (is.null(db_pool)) {
    # Try to get from global environment
    if (exists("db_pool", envir = .GlobalEnv)) {
      db_pool <- get("db_pool", envir = .GlobalEnv)
    } else {
      warning("Database pool not available")
      return(list(
        total_documents = 0,
        states_percentage = 0,
        municipalities_percentage = 0,
        date_range_years = 0,
        last_updated = NA
      ))
    }
  }
  
  tryCatch({
    cat("📊 Getting LexML dashboard metrics...\n")
    
    # Main metrics query
    metrics_query <- "
      SELECT 
        COUNT(*) as total_documents,
        COUNT(DISTINCT CASE WHEN jurisdicao = 'State' THEN localidade END) as states_with_docs,
        COUNT(DISTINCT CASE WHEN jurisdicao = 'Municipal' THEN localidade END) as municipalities_with_docs,
        MIN(data) as min_date,
        MAX(data) as max_date,
        MAX(data_coleta) as last_updated
      FROM lexml_documents 
      WHERE data IS NOT NULL
    "
    
    result <- dbGetQuery(db_pool, metrics_query)
    
    if (nrow(result) > 0) {
      row <- result[1, ]
      
      # Calculate percentages (27 states + DF = 28 total federal entities)
      states_percentage <- round((row$states_with_docs / 28) * 100, 1)
      
      # Approximate number of municipalities in Brazil (5,570)
      municipalities_percentage <- round((row$municipalities_with_docs / 5570) * 100, 1)
      
      # Calculate date range in years
      if (!is.na(row$min_date) && !is.na(row$max_date)) {
        min_year <- as.numeric(format(as.Date(row$min_date), "%Y"))
        max_year <- as.numeric(format(as.Date(row$max_date), "%Y"))
        date_range_years <- max_year - min_year
      } else {
        date_range_years <- 0
      }
      
      metrics <- list(
        total_documents = as.numeric(row$total_documents),
        states_percentage = states_percentage,
        municipalities_percentage = municipalities_percentage,
        date_range_years = date_range_years,
        last_updated = row$last_updated,
        min_date = row$min_date,
        max_date = row$max_date
      )
      
      cat("✅ Dashboard metrics calculated:\n")
      cat("  Total documents:", metrics$total_documents, "\n")
      cat("  States with docs:", row$states_with_docs, "/28 (", states_percentage, "%)\n")
      cat("  Municipalities with docs:", row$municipalities_with_docs, "/5570 (", municipalities_percentage, "%)\n")
      cat("  Date range:", date_range_years, "years\n")
      
      return(metrics)
    }
    
    return(list(
      total_documents = 0,
      states_percentage = 0,
      municipalities_percentage = 0,
      date_range_years = 0,
      last_updated = NA
    ))
    
  }, error = function(e) {
    cat("❌ Error getting dashboard metrics:", e$message, "\n")
    return(list(
      total_documents = 0,
      states_percentage = 0,
      municipalities_percentage = 0,
      date_range_years = 0,
      last_updated = NA
    ))
  })
}

#' Get geographic data for maps by jurisdiction level
#' @param db_pool Database connection pool
#' @param layer Jurisdiction layer: "federal", "regional", "state", "municipal"
#' @param category Optional category filter: NULL (all), "Legislação", "Jurisprudência"
#' @param selected_state For municipal layer, which state to focus on
#' @return Data frame with geographic aggregation
get_lexml_geographic_data <- function(db_pool = NULL, layer = "state", category = NULL, selected_state = NULL) {
  if (is.null(db_pool)) {
    if (exists("db_pool", envir = .GlobalEnv)) {
      db_pool <- get("db_pool", envir = .GlobalEnv)
    } else {
      warning("Database pool not available")
      return(data.frame())
    }
  }
  
  tryCatch({
    cat("🗺️ Getting geographic data for layer:", layer, "category:", category %||% "all", "\n")
    
    # Base WHERE clause
    where_clause <- "WHERE 1=1"
    if (!is.null(category)) {
      where_clause <- paste0(where_clause, " AND categoria = '", category, "'")
    }
    
    if (layer == "federal") {
      # Federal documents - aggregate to single row
      query <- paste0("
        SELECT 
          'Federal' as name,
          'Brasil' as full_name,
          COUNT(*) as doc_count,
          'federal' as level
        FROM lexml_documents 
        ", where_clause, " 
        AND jurisdicao = 'Federal'
      ")
      
    } else if (layer == "regional") {
      # Regional aggregation - we'll post-process this
      query <- paste0("
        SELECT 
          localidade as state_name,
          COUNT(*) as doc_count
        FROM lexml_documents 
        ", where_clause, " 
        AND jurisdicao = 'State' 
        AND localidade IS NOT NULL
        GROUP BY localidade
      ")
      
    } else if (layer == "state") {
      # State level aggregation
      query <- paste0("
        SELECT 
          localidade as name,
          localidade as full_name,
          COUNT(*) as doc_count,
          'state' as level
        FROM lexml_documents 
        ", where_clause, " 
        AND jurisdicao = 'State' 
        AND localidade IS NOT NULL
        GROUP BY localidade
        ORDER BY doc_count DESC
      ")
      
    } else if (layer == "municipal") {
      # Municipal level - filter by state if provided
      state_filter <- ""
      if (!is.null(selected_state)) {
        state_filter <- paste0(" AND localidade LIKE '%", selected_state, "%'")
      }
      
      query <- paste0("
        SELECT 
          localidade as name,
          localidade as full_name,
          COUNT(*) as doc_count,
          'municipal' as level
        FROM lexml_documents 
        ", where_clause, " 
        AND jurisdicao = 'Municipal' 
        AND localidade IS NOT NULL
        ", state_filter, "
        GROUP BY localidade
        ORDER BY doc_count DESC
        LIMIT 100
      ")
    }
    
    result <- dbGetQuery(db_pool, query)
    
    # Post-process for regional aggregation
    if (layer == "regional" && nrow(result) > 0) {
      # Map states to regions
      result$region <- sapply(result$state_name, function(state) {
        for (region_name in names(BRAZIL_REGIONS)) {
          if (state %in% BRAZIL_REGIONS[[region_name]]) {
            return(region_name)
          }
        }
        return("Unknown")
      })
      
      # Aggregate by region
      regional_data <- result %>%
        group_by(region) %>%
        summarise(doc_count = sum(doc_count), .groups = 'drop') %>%
        rename(name = region) %>%
        mutate(
          full_name = name,
          level = "regional"
        ) %>%
        arrange(desc(doc_count))
      
      result <- as.data.frame(regional_data)
    }
    
    if (nrow(result) > 0) {
      cat("✅ Geographic data retrieved:", nrow(result), "entities for", layer, "level\n")
      if (nrow(result) <= 10) {
        cat("  Top entities:\n")
        for (i in 1:min(5, nrow(result))) {
          cat("    ", result$name[i], ":", result$doc_count[i], "docs\n")
        }
      }
    } else {
      cat("⚠️ No geographic data found for", layer, "level\n")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Error getting geographic data:", e$message, "\n")
    return(data.frame())
  })
}

#' Get available states for state selection dropdown
#' @param db_pool Database connection pool
#' @return Character vector of state names
get_available_states <- function(db_pool = NULL) {
  if (is.null(db_pool)) {
    if (exists("db_pool", envir = .GlobalEnv)) {
      db_pool <- get("db_pool", envir = .GlobalEnv)
    } else {
      return(character(0))
    }
  }
  
  tryCatch({
    result <- dbGetQuery(db_pool, "
      SELECT DISTINCT localidade
      FROM lexml_documents 
      WHERE jurisdicao = 'State' 
        AND localidade IS NOT NULL
      ORDER BY localidade
    ")
    
    if (nrow(result) > 0) {
      return(result$localidade)
    } else {
      return(character(0))
    }
    
  }, error = function(e) {
    cat("Error getting available states:", e$message, "\n")
    return(character(0))
  })
}

#' Map state name to region
#' @param state_name Full state name
#' @return Region name
get_state_region <- function(state_name) {
  for (region_name in names(BRAZIL_REGIONS)) {
    if (state_name %in% BRAZIL_REGIONS[[region_name]]) {
      return(region_name)
    }
  }
  return("Unknown")
}

#' Get latest update summary for About tab
#' @param db_pool Database connection pool  
#' @return List with update information
get_lexml_update_summary <- function(db_pool = NULL) {
  if (is.null(db_pool)) {
    if (exists("db_pool", envir = .GlobalEnv)) {
      db_pool <- get("db_pool", envir = .GlobalEnv)
    } else {
      return(list(
        last_updated = "Unknown",
        total_records = 0,
        categories = data.frame(),
        jurisdictions = data.frame()
      ))
    }
  }
  
  tryCatch({
    # Get latest update timestamp and totals
    summary_query <- "
      SELECT 
        MAX(data_coleta) as last_updated,
        COUNT(*) as total_records,
        MIN(data) as earliest_date,
        MAX(data) as latest_date
      FROM lexml_documents
    "
    
    summary <- dbGetQuery(db_pool, summary_query)
    
    # Get category distribution
    category_query <- "
      SELECT 
        categoria,
        COUNT(*) as count,
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents), 1) as percentage
      FROM lexml_documents
      GROUP BY categoria
      ORDER BY count DESC
    "
    
    categories <- dbGetQuery(db_pool, category_query)
    
    # Get jurisdiction distribution
    jurisdiction_query <- "
      SELECT 
        jurisdicao,
        COUNT(*) as count,
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents), 1) as percentage
      FROM lexml_documents
      WHERE jurisdicao IS NOT NULL
      GROUP BY jurisdicao
      ORDER BY count DESC
    "
    
    jurisdictions <- dbGetQuery(db_pool, jurisdiction_query)
    
    return(list(
      last_updated = summary$last_updated[1],
      total_records = as.numeric(summary$total_records[1]),
      earliest_date = summary$earliest_date[1],
      latest_date = summary$latest_date[1],
      categories = categories,
      jurisdictions = jurisdictions
    ))
    
  }, error = function(e) {
    cat("Error getting update summary:", e$message, "\n")
    return(list(
      last_updated = "Error",
      total_records = 0,
      categories = data.frame(),
      jurisdictions = data.frame()
    ))
  })
}

cat("✅ LexML Geographic Analytics module loaded\n")