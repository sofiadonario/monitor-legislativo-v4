# Simplified Maps and Geographic Data Fix
# Works without leaflet and plotly packages
# Focuses on core data functionality

# Load required libraries
library(dplyr)
library(stringr)

# ============================================================================
# 1. FIX DATA STRUCTURE ISSUES
# ============================================================================

#' Fix document categorization and geographic data
#' This addresses the core issue where 86% of documents are marked as "BR"
fix_document_geographic_data <- function() {
  if (!exists("database_connected") || !exists("db_pool")) {
    cat("❌ Database not connected\n")
    return(FALSE)
  }
  
  if (!database_connected || is.null(db_pool)) {
    cat("❌ Database not connected\n")
    return(FALSE)
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # 1. Fix categoria values to match expected strings
    cat("🔧 Fixing document categories...\n")
    dbExecute(conn, "
      UPDATE documents 
      SET categoria = 'Legislação'
      WHERE categoria IN ('Legislacao', 'legislacao', 'LEGISLAÇÃO')
    ")
    
    dbExecute(conn, "
      UPDATE documents 
      SET categoria = 'Jurisprudência'
      WHERE categoria IN ('Jurisprudencia', 'jurisprudencia', 'JURISPRUDÊNCIA')
    ")
    
    dbExecute(conn, "
      UPDATE documents 
      SET categoria = 'Doutrina'
      WHERE categoria IN ('doutrina', 'DOUTRINA', 'library')
    ")
    
    # 2. Fix federal documents - map "BR" to "DF" for Brasília
    cat("🔧 Fixing federal document locations...\n")
    dbExecute(conn, "
      UPDATE documents 
      SET estado = 'DF', municipality = 'Brasília'
      WHERE estado = 'BR' AND (municipality IS NULL OR municipality = '')
    ")
    
    # 3. Extract state information from URN fields where possible
    cat("🔧 Extracting state information from URN fields...\n")
    dbExecute(conn, "
      UPDATE documents 
      SET estado = CASE 
        WHEN URN LIKE '%/sp/%' THEN 'SP'
        WHEN URN LIKE '%/rj/%' THEN 'RJ'
        WHEN URN LIKE '%/mg/%' THEN 'MG'
        WHEN URN LIKE '%/rs/%' THEN 'RS'
        WHEN URN LIKE '%/pr/%' THEN 'PR'
        WHEN URN LIKE '%/sc/%' THEN 'SC'
        WHEN URN LIKE '%/ba/%' THEN 'BA'
        WHEN URN LIKE '%/go/%' THEN 'GO'
        WHEN URN LIKE '%/pe/%' THEN 'PE'
        WHEN URN LIKE '%/ce/%' THEN 'CE'
        WHEN URN LIKE '%/pa/%' THEN 'PA'
        WHEN URN LIKE '%/ma/%' THEN 'MA'
        WHEN URN LIKE '%/pi/%' THEN 'PI'
        WHEN URN LIKE '%/rn/%' THEN 'RN'
        WHEN URN LIKE '%/se/%' THEN 'SE'
        WHEN URN LIKE '%/al/%' THEN 'AL'
        WHEN URN LIKE '%/pb/%' THEN 'PB'
        WHEN URN LIKE '%/es/%' THEN 'ES'
        WHEN URN LIKE '%/mt/%' THEN 'MT'
        WHEN URN LIKE '%/ms/%' THEN 'MS'
        WHEN URN LIKE '%/ro/%' THEN 'RO'
        WHEN URN LIKE '%/ac/%' THEN 'AC'
        WHEN URN LIKE '%/ap/%' THEN 'AP'
        WHEN URN LIKE '%/rr/%' THEN 'RR'
        WHEN URN LIKE '%/am/%' THEN 'AM'
        WHEN URN LIKE '%/to/%' THEN 'TO'
        ELSE estado
      END
      WHERE estado = 'BR' OR estado IS NULL
    ")
    
    cat("✅ Document geographic data fixed\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error fixing document data:", e$message, "\n")
    return(FALSE)
  })
}

# ============================================================================
# 2. CREATE WORKING MAP DATA FUNCTION
# ============================================================================

#' Get working map data with proper state coordinates
#' This replaces the problematic get_simple_map_data() function
get_working_map_data <- function() {
  if (!exists("database_connected") || !exists("db_pool")) {
    return(data.frame())
  }
  
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Get document counts by state with proper categorization
    result <- dbGetQuery(conn, "
      SELECT 
        estado as abbrev,
        COUNT(*) as total_docs,
        SUM(CASE WHEN categoria = 'Legislação' THEN 1 ELSE 0 END) as legislacao,
        SUM(CASE WHEN categoria = 'Jurisprudência' THEN 1 ELSE 0 END) as jurisprudencia,
        SUM(CASE WHEN categoria = 'Doutrina' THEN 1 ELSE 0 END) as doutrina,
        SUM(CASE WHEN categoria NOT IN ('Legislação', 'Jurisprudência', 'Doutrina') THEN 1 ELSE 0 END) as outros
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado
      ORDER BY total_docs DESC
    ")
    
    if (nrow(result) == 0) {
      cat("⚠️ No state data found, returning empty dataframe\n")
      return(data.frame())
    }
    
    # Add state information and coordinates
    state_info <- data.frame(
      abbrev = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                 "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                 "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
      name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
               "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão", 
               "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
               "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", 
               "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", 
               "Roraima", "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
      region = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste", 
                 "Centro-Oeste", "Sudeste", "Centro-Oeste", "Nordeste", 
                 "Centro-Oeste", "Centro-Oeste", "Sudeste", "Norte", "Nordeste", 
                 "Sul", "Nordeste", "Nordeste", "Sudeste", "Nordeste", 
                 "Sul", "Norte", "Norte", "Sul", "Sudeste", "Nordeste", "Norte"),
      capital = c("Rio Branco", "Maceió", "Macapá", "Manaus", "Salvador", "Fortaleza", 
                  "Brasília", "Vitória", "Goiânia", "São Luís", "Cuiabá", 
                  "Campo Grande", "Belo Horizonte", "Belém", "João Pessoa", 
                  "Curitiba", "Recife", "Teresina", "Rio de Janeiro", "Natal", 
                  "Porto Alegre", "Porto Velho", "Boa Vista", "Florianópolis", 
                  "São Paulo", "Aracaju", "Palmas"),
      lat = c(-8.77, -9.71, 0.00, -3.07, -12.96, -5.20, -15.83, -19.19, -16.64, -2.55,
              -15.60, -20.51, -18.10, -5.53, -7.06, -24.89, -8.28, -8.28, -22.84, -5.22,
              -30.01, -8.83, 2.73, -27.33, -23.55, -10.90, -10.25),
      lng = c(-70.55, -36.82, -51.77, -65.74, -41.58, -39.73, -47.86, -40.34, -49.31, -45.28,
              -56.10, -54.54, -45.00, -52.00, -36.78, -51.22, -38.95, -43.68, -43.68, -36.95,
              -52.09, -62.76, -61.33, -50.16, -48.64, -37.86, -48.25),
      stringsAsFactors = FALSE
    )
    
    # Merge with document counts
    final_result <- result %>%
      left_join(state_info, by = "abbrev") %>%
      filter(!is.na(name))  # Only include states with coordinates
    
    cat("✅ Map data prepared:", nrow(final_result), "states with data\n")
    return(final_result)
    
  }, error = function(e) {
    cat("❌ Error getting map data:", e$message, "\n")
    return(data.frame())
  })
}

# ============================================================================
# 3. CREATE SIMPLIFIED MAP FUNCTIONS (TEXT-BASED)
# ============================================================================

#' Create simple text-based map summary
create_simple_map_summary <- function() {
  tryCatch({
    map_data <- get_working_map_data()
    
    if (nrow(map_data) == 0) {
      cat("⚠️ No map data available\n")
      return("No geographic data available")
    }
    
    # Create a simple text summary
    summary_text <- paste0(
      "Map Summary:\n",
      "Total states with documents: ", nrow(map_data), "\n",
      "Top 5 states by document count:\n"
    )
    
    # Add top 5 states
    top_states <- head(map_data[order(-map_data$total_docs), ], 5)
    for (i in 1:nrow(top_states)) {
      state <- top_states[i, ]
      summary_text <- paste0(
        summary_text,
        "  ", state$name, " (", state$abbrev, "): ", state$total_docs, " documents\n"
      )
    }
    
    cat("✅ Simple map summary created\n")
    return(summary_text)
    
  }, error = function(e) {
    cat("❌ Error creating map summary:", e$message, "\n")
    return("Error creating map summary")
  })
}

# ============================================================================
# 4. CREATE STATE DISTRIBUTION FUNCTIONS
# ============================================================================

#' Get state distribution for dashboard
get_state_distribution <- function() {
  if (!exists("database_connected") || !exists("db_pool")) {
    return(data.frame())
  }
  
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    result <- dbGetQuery(conn, "
      SELECT 
        estado,
        COUNT(*) as count
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado
      ORDER BY count DESC
    ")
    
    cat("📊 State distribution:", nrow(result), "states\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error getting state distribution:", e$message, "\n")
    return(data.frame())
  })
}

#' Get municipality distribution for dashboard
get_municipality_distribution <- function() {
  if (!exists("database_connected") || !exists("db_pool")) {
    return(data.frame())
  }
  
  if (!database_connected || is.null(db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    result <- dbGetQuery(conn, "
      SELECT 
        municipality,
        COUNT(*) as count
      FROM documents 
      WHERE municipality IS NOT NULL AND municipality != ''
      GROUP BY municipality
      ORDER BY count DESC
      LIMIT 20
    ")
    
    cat("📊 Municipality distribution:", nrow(result), "municipalities\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error getting municipality distribution:", e$message, "\n")
    return(data.frame())
  })
}

# ============================================================================
# 5. CREATE SIMPLE VISUALIZATION FUNCTIONS
# ============================================================================

#' Create simple text-based state distribution
create_simple_state_distribution <- function() {
  state_dist <- get_state_distribution()
  
  if (nrow(state_dist) == 0) {
    return("No state data available")
  }
  
  # Create a simple text summary
  summary_text <- paste0(
    "State Distribution:\n",
    "Total states: ", nrow(state_dist), "\n",
    "Top 10 states by document count:\n"
  )
  
  # Add top 10 states
  top_states <- head(state_dist, 10)
  for (i in 1:nrow(top_states)) {
    state <- top_states[i, ]
    summary_text <- paste0(
      summary_text,
      "  ", state$estado, ": ", state$count, " documents\n"
    )
  }
  
  return(summary_text)
}

#' Create simple text-based municipality distribution
create_simple_municipality_distribution <- function() {
  mun_dist <- get_municipality_distribution()
  
  if (nrow(mun_dist) == 0) {
    return("No municipality data available")
  }
  
  # Create a simple text summary
  summary_text <- paste0(
    "Municipality Distribution:\n",
    "Total municipalities: ", nrow(mun_dist), "\n",
    "Top 10 municipalities by document count:\n"
  )
  
  # Add top 10 municipalities
  top_municipalities <- head(mun_dist, 10)
  for (i in 1:nrow(top_municipalities)) {
    mun <- top_municipalities[i, ]
    summary_text <- paste0(
      summary_text,
      "  ", mun$municipality, ": ", mun$count, " documents\n"
    )
  }
  
  return(summary_text)
}

# ============================================================================
# 6. OVERRIDE EXISTING FUNCTIONS
# ============================================================================

# Override the problematic get_simple_map_data function
if (exists("get_simple_map_data")) {
  cat("🔄 Overriding get_simple_map_data with working version\n")
}

# Make functions available globally
assign("get_working_map_data", get_working_map_data, envir = .GlobalEnv)
assign("create_simple_map_summary", create_simple_map_summary, envir = .GlobalEnv)
assign("get_state_distribution", get_state_distribution, envir = .GlobalEnv)
assign("get_municipality_distribution", get_municipality_distribution, envir = .GlobalEnv)
assign("create_simple_state_distribution", create_simple_state_distribution, envir = .GlobalEnv)
assign("create_simple_municipality_distribution", create_simple_municipality_distribution, envir = .GlobalEnv)
assign("fix_document_geographic_data", fix_document_geographic_data, envir = .GlobalEnv)

cat("✅ Simplified maps and geographic data fix loaded\n")
cat("📊 Functions available:\n")
cat("  - get_working_map_data()\n")
cat("  - create_simple_map_summary()\n")
cat("  - get_state_distribution()\n")
cat("  - get_municipality_distribution()\n")
cat("  - create_simple_state_distribution()\n")
cat("  - create_simple_municipality_distribution()\n")
cat("  - fix_document_geographic_data()\n")
cat("\n")
cat("📝 Note: This is a simplified version that works without leaflet/plotly packages\n")
cat("📝 For full map functionality, install: leaflet, plotly, DBI, RPostgres\n") 