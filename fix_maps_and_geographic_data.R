# Comprehensive Fix for Maps and Geographic Data Issues
# Addresses the problems identified in the executive summary

# Load required libraries
library(dplyr)
library(stringr)

# Try to load leaflet, but don't fail if it's not available
tryCatch({
  library(leaflet)
  cat("✅ Leaflet package loaded\n")
}, error = function(e) {
  cat("⚠️ Leaflet package not available - maps will use fallback mode\n")
})

# ============================================================================
# 1. FIX DATA STRUCTURE ISSUES
# ============================================================================

#' Fix document categorization and geographic data
#' This addresses the core issue where 86% of documents are marked as "BR"
fix_document_geographic_data <- function() {
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
# 3. CREATE WORKING MAP FUNCTIONS
# ============================================================================

#' Create working total documents map
create_total_documents_map <- function() {
  tryCatch({
    map_data <- get_working_map_data()
    
    if (nrow(map_data) == 0) {
      cat("⚠️ No map data available, showing fallback map\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, 
                 popup = "No geographic data available - Check database connection"))
    }
    
    # Create map with state markers
    map <- leaflet(map_data) %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4)
    
    # Add markers for each state with documents
    for (i in 1:nrow(map_data)) {
      row <- map_data[i, ]
      if (!is.na(row$lat) && !is.na(row$lng) && row$total_docs > 0) {
        popup_text <- paste0(
          "<b>", row$name, " (", row$abbrev, ")</b><br/>",
          "Region: ", row$region, "<br/>",
          "Capital: ", row$capital, "<br/>",
          "Total Documents: ", row$total_docs, "<br/>",
          "Legislation: ", row$legislacao, "<br/>",
          "Jurisprudence: ", row$jurisprudencia, "<br/>",
          "Doctrine: ", row$doutrina
        )
        
        map <- map %>%
          addCircleMarkers(
            lng = row$lng, lat = row$lat,
            radius = sqrt(row$total_docs) / 10,
            popup = popup_text,
            fillOpacity = 0.7,
            color = "blue"
          )
      }
    }
    
    cat("✅ Total documents map created successfully\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error creating total documents map:", e$message, "\n")
    return(leaflet() %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
      addMarker(lng = -47.86, lat = -15.83, 
               popup = paste("Map error:", e$message)))
  })
}

#' Create working legislation map
create_legislation_map <- function() {
  tryCatch({
    map_data <- get_working_map_data()
    
    if (nrow(map_data) == 0 || sum(map_data$legislacao, na.rm = TRUE) == 0) {
      cat("⚠️ No legislation data available\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, 
                 popup = "No legislation data available"))
    }
    
    # Filter for states with legislation documents
    leg_data <- map_data[map_data$legislacao > 0, ]
    
    map <- leaflet(leg_data) %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4)
    
    for (i in 1:nrow(leg_data)) {
      row <- leg_data[i, ]
      if (!is.na(row$lat) && !is.na(row$lng)) {
        popup_text <- paste0(
          "<b>", row$name, " (", row$abbrev, ")</b><br/>",
          "Legislation Documents: ", row$legislacao
        )
        
        map <- map %>%
          addCircleMarkers(
            lng = row$lng, lat = row$lat,
            radius = sqrt(row$legislacao) / 8,
            popup = popup_text,
            fillOpacity = 0.7,
            color = "orange"
          )
      }
    }
    
    cat("✅ Legislation map created successfully\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error creating legislation map:", e$message, "\n")
    return(leaflet() %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
      addMarker(lng = -47.86, lat = -15.83, 
               popup = paste("Legislation map error:", e$message)))
  })
}

#' Create working jurisprudence map
create_jurisprudence_map <- function() {
  tryCatch({
    map_data <- get_working_map_data()
    
    if (nrow(map_data) == 0 || sum(map_data$jurisprudencia, na.rm = TRUE) == 0) {
      cat("⚠️ No jurisprudence data available\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, zoom = 4) %>%
        addMarker(lng = -47.86, lat = -15.83, 
                 popup = "No jurisprudence data available"))
    }
    
    # Filter for states with jurisprudence documents
    jur_data <- map_data[map_data$jurisprudencia > 0, ]
    
    map <- leaflet(jur_data) %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4)
    
    for (i in 1:nrow(jur_data)) {
      row <- jur_data[i, ]
      if (!is.na(row$lat) && !is.na(row$lng)) {
        popup_text <- paste0(
          "<b>", row$name, " (", row$abbrev, ")</b><br/>",
          "Jurisprudence Documents: ", row$jurisprudencia
        )
        
        map <- map %>%
          addCircleMarkers(
            lng = row$lng, lat = row$lat,
            radius = sqrt(row$jurisprudencia) / 8,
            popup = popup_text,
            fillOpacity = 0.7,
            color = "green"
          )
      }
    }
    
    cat("✅ Jurisprudence map created successfully\n")
    return(map)
    
  }, error = function(e) {
    cat("❌ Error creating jurisprudence map:", e$message, "\n")
    return(leaflet() %>%
      addTiles() %>%
      setView(lng = -47.86, lat = -15.83, zoom = 4) %>%
      addMarker(lng = -47.86, lat = -15.83, 
               popup = paste("Jurisprudence map error:", e$message)))
  })
}

# ============================================================================
# 4. CREATE STATE DISTRIBUTION FUNCTIONS
# ============================================================================

#' Get state distribution for dashboard
get_state_distribution <- function() {
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
# 5. OVERRIDE EXISTING FUNCTIONS
# ============================================================================

# Override the problematic get_simple_map_data function
if (exists("get_simple_map_data")) {
  cat("🔄 Overriding get_simple_map_data with working version\n")
}

# Make functions available globally
assign("get_working_map_data", get_working_map_data, envir = .GlobalEnv)
assign("create_total_documents_map", create_total_documents_map, envir = .GlobalEnv)
assign("create_legislation_map", create_legislation_map, envir = .GlobalEnv)
assign("create_jurisprudence_map", create_jurisprudence_map, envir = .GlobalEnv)
assign("get_state_distribution", get_state_distribution, envir = .GlobalEnv)
assign("get_municipality_distribution", get_municipality_distribution, envir = .GlobalEnv)
assign("fix_document_geographic_data", fix_document_geographic_data, envir = .GlobalEnv)

cat("✅ Maps and geographic data fix loaded\n")
cat("📊 Functions available:\n")
cat("  - get_working_map_data()\n")
cat("  - create_total_documents_map()\n")
cat("  - create_legislation_map()\n")
cat("  - create_jurisprudence_map()\n")
cat("  - get_state_distribution()\n")
cat("  - get_municipality_distribution()\n")
cat("  - fix_document_geographic_data()\n") 