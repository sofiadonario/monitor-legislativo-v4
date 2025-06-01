# ============================================================================
# GEOSPATIAL PACKAGES FIX FOR RAILWAY DEPLOYMENT
# ============================================================================
#
# This script ensures geospatial packages are available or provides fallbacks
# for Railway deployment where sf, leaflet, and geobr might not install properly
#
# ============================================================================

cat("🗺️ GEOSPATIAL PACKAGES LOADER\n")
cat("==============================\n")

# Try to install and load leaflet
leaflet_available <- tryCatch({
  if (!requireNamespace("leaflet", quietly = TRUE)) {
    cat("📦 Installing leaflet...\n")
    install.packages("leaflet", dependencies = TRUE, repos = "https://cran.rstudio.com/")
  }
  library(leaflet)
  cat("✅ leaflet package loaded successfully\n")
  TRUE
}, error = function(e) {
  cat("❌ leaflet package not available:", e$message, "\n")
  cat("🔄 Using leaflet fallbacks\n")
  FALSE
})

# Try to install and load sf (Simple Features)
sf_available <- tryCatch({
  if (!requireNamespace("sf", quietly = TRUE)) {
    cat("📦 Installing sf...\n")
    install.packages("sf", dependencies = TRUE, repos = "https://cran.rstudio.com/")
  }
  library(sf)
  cat("✅ sf package loaded successfully\n")
  TRUE
}, error = function(e) {
  cat("❌ sf package not available:", e$message, "\n")
  cat("🔄 Using sf fallbacks\n")
  FALSE
})

# Try to install and load geobr (Brazilian geographic data)
geobr_available <- tryCatch({
  if (!requireNamespace("geobr", quietly = TRUE)) {
    cat("📦 Installing geobr...\n")
    install.packages("geobr", dependencies = TRUE, repos = "https://cran.rstudio.com/")
  }
  library(geobr)
  cat("✅ geobr package loaded successfully\n")
  TRUE
}, error = function(e) {
  cat("❌ geobr package not available:", e$message, "\n")
  cat("🔄 Using geobr fallbacks\n")
  FALSE
})

# Create fallback functions for leaflet
if (!leaflet_available) {
  leaflet <- function(...) {
    cat("⚠️ leaflet not available, returning mock map object\n")
    list(
      addTiles = function(...) return(list()),
      addPolygons = function(...) return(list()),
      addMarkers = function(...) return(list()),
      setView = function(...) return(list())
    )
  }
  
  addTiles <- function(map, ...) return(map)
  addPolygons <- function(map, ...) return(map)
  addMarkers <- function(map, ...) return(map)
  setView <- function(map, ...) return(map)
  
  # Export to global environment
  assign("leaflet", leaflet, envir = .GlobalEnv)
  assign("addTiles", addTiles, envir = .GlobalEnv)
  assign("addPolygons", addPolygons, envir = .GlobalEnv)
  assign("addMarkers", addMarkers, envir = .GlobalEnv)
  assign("setView", setView, envir = .GlobalEnv)
}

# Create fallback functions for sf
if (!sf_available) {
  st_read <- function(file, ...) {
    cat("⚠️ sf not available, returning empty spatial data\n")
    data.frame(
      name = character(0),
      geometry = character(0)
    )
  }
  
  st_as_sf <- function(data, ...) {
    cat("⚠️ sf not available, returning original data\n")
    return(data)
  }
  
  st_transform <- function(data, ...) {
    cat("⚠️ sf not available, returning original data\n")
    return(data)
  }
  
  # Export to global environment
  assign("st_read", st_read, envir = .GlobalEnv)
  assign("st_as_sf", st_as_sf, envir = .GlobalEnv)
  assign("st_transform", st_transform, envir = .GlobalEnv)
}

# Create fallback functions for geobr
if (!geobr_available) {
  read_state <- function(...) {
    cat("⚠️ geobr not available, using fallback Brazilian states data\n")
    
    # Return basic Brazilian states data
    states_data <- data.frame(
      code_state = c("11", "12", "13", "14", "15", "16", "17", "21", "22", "23", "24", 
                     "25", "26", "27", "28", "29", "31", "32", "33", "35", "41", "42", 
                     "43", "50", "51", "52", "53"),
      name_state = c("Rondônia", "Acre", "Amazonas", "Roraima", "Pará", "Amapá", "Tocantins",
                     "Maranhão", "Piauí", "Ceará", "Rio Grande do Norte", "Paraíba", 
                     "Pernambuco", "Alagoas", "Sergipe", "Bahia", "Minas Gerais", 
                     "Espírito Santo", "Rio de Janeiro", "São Paulo", "Paraná", 
                     "Santa Catarina", "Rio Grande do Sul", "Mato Grosso do Sul", 
                     "Mato Grosso", "Goiás", "Distrito Federal"),
      abbrev_state = c("RO", "AC", "AM", "RR", "PA", "AP", "TO", "MA", "PI", "CE", "RN", 
                       "PB", "PE", "AL", "SE", "BA", "MG", "ES", "RJ", "SP", "PR", "SC", 
                       "RS", "MS", "MT", "GO", "DF"),
      stringsAsFactors = FALSE
    )
    
    return(states_data)
  }
  
  read_municipality <- function(...) {
    cat("⚠️ geobr not available, using fallback Brazilian municipalities data\n")
    
    # Return basic municipalities data (limited sample)
    municipalities_data <- data.frame(
      code_muni = c("3550308", "3304557", "2304400", "4106902", "5300108"),
      name_muni = c("São Paulo", "Rio de Janeiro", "Fortaleza", "Curitiba", "Brasília"),
      code_state = c("35", "33", "23", "41", "53"),
      abbrev_state = c("SP", "RJ", "CE", "PR", "DF"),
      name_state = c("São Paulo", "Rio de Janeiro", "Ceará", "Paraná", "Distrito Federal"),
      stringsAsFactors = FALSE
    )
    
    return(municipalities_data)
  }
  
  # Export to global environment
  assign("read_state", read_state, envir = .GlobalEnv)
  assign("read_municipality", read_municipality, envir = .GlobalEnv)
}

# Store package availability status
geospatial_status <- list(
  leaflet_available = leaflet_available,
  sf_available = sf_available,
  geobr_available = geobr_available,
  fallbacks_loaded = TRUE,
  loaded_at = Sys.time()
)

assign("GEOSPATIAL_PACKAGES_STATUS", geospatial_status, envir = .GlobalEnv)

# Print final status
cat("\n🗺️ GEOSPATIAL PACKAGES STATUS:\n")
cat("   leaflet:", ifelse(leaflet_available, "✅ Available", "⚠️ Using fallbacks"), "\n")
cat("   sf:", ifelse(sf_available, "✅ Available", "⚠️ Using fallbacks"), "\n") 
cat("   geobr:", ifelse(geobr_available, "✅ Available", "⚠️ Using fallbacks"), "\n")
cat("==============================\n")