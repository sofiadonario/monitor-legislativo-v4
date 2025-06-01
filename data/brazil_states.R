# Brazilian States Reference Data
# This file contains comprehensive data about Brazilian states including
# coordinates, population, regions, and other metadata

brazil_states_data <- data.frame(
  state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                 "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                 "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
  
  state_name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                 "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                 "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                 "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro",
                 "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima", 
                 "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
  
  lat = c(-9.974, -9.666, 0.902, -5.083, -13.3, -5.2, -15.78, -20.297, -16.686, -3.71,
          -15.601, -21.2, -19.9208, -4.26, -7.24, -25.428, -8.047, -7.39, -22.91, -5.778,
          -30.034, -10.944, 2.82, -27.595, -23.55, -10.574, -10.25),
  
  lng = c(-70.504, -36.661, -51.695, -63.083, -41.7, -38.9, -47.93, -40.842, -49.265, -45.08,
          -56.097, -54.6, -43.9386, -52.66, -36.78, -49.265, -35.027, -42.11, -43.196, -36.577,
          -51.217, -62.829, -60.675, -48.548, -46.636, -37.343, -48.36),
  
  population = c(906876, 3365351, 877613, 4269995, 14985284, 9240580, 3094325, 4108508, 
                 7206589, 7153262, 3567234, 2839188, 21411923, 8777124, 4059905, 
                 11597484, 9674793, 3289290, 17463349, 3560903, 11466630, 1815278, 
                 652713, 7338473, 46649132, 2338474, 1607363),
  
  region = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste", "Centro-Oeste", 
             "Sudeste", "Centro-Oeste", "Nordeste", "Centro-Oeste", "Centro-Oeste", "Sudeste", 
             "Norte", "Nordeste", "Sul", "Nordeste", "Nordeste", "Sudeste", "Nordeste", 
             "Sul", "Norte", "Norte", "Sul", "Sudeste", "Nordeste", "Norte"),
  
  region_code = c("N", "NE", "N", "N", "NE", "NE", "CO", "SE", "CO", "NE", "CO", "CO", 
                  "SE", "N", "NE", "S", "NE", "NE", "SE", "NE", "S", "N", "N", "S", 
                  "SE", "NE", "N"),
  
  area_km2 = c(164173.43, 27843.30, 142470.76, 1559167.89, 564760.43, 148894.44, 5760.78,
               46074.45, 340203.33, 329651.50, 903208.05, 357142.08, 586519.73, 1245870.80,
               56467.24, 199305.24, 98076.02, 251756.52, 43751.59, 52809.60, 281707.16,
               237765.38, 224273.83, 95730.68, 248219.49, 21926.02, 277720.41),
  
  gdp_billions = c(16.48, 63.20, 18.47, 116.02, 353.50, 195.51, 285.83, 191.02, 242.94,
                   112.84, 204.83, 142.16, 771.30, 215.94, 70.29, 550.74, 220.82, 59.70,
                   936.70, 77.00, 581.28, 52.07, 14.72, 369.60, 2719.76, 50.49, 43.65),
  
  hdi = c(0.663, 0.631, 0.708, 0.674, 0.660, 0.682, 0.824, 0.740, 0.735, 0.639,
          0.725, 0.729, 0.731, 0.646, 0.658, 0.749, 0.673, 0.646, 0.761, 0.684,
          0.746, 0.690, 0.707, 0.774, 0.783, 0.665, 0.699),
  
  stringsAsFactors = FALSE
)

# Export the data
brazil_states <- brazil_states_data

# Function to get state info
get_brazil_state_info <- function(state_code = NULL) {
  if (is.null(state_code)) {
    return(brazil_states)
  }
  
  state_info <- brazil_states[brazil_states$state_code == state_code, ]
  if (nrow(state_info) == 0) {
    return(NULL)
  }
  return(state_info)
}

# Function to get states by region
get_states_by_region <- function(region_name) {
  brazil_states[brazil_states$region == region_name, ]
}

# Function to get state coordinates
get_state_coordinates <- function() {
  brazil_states[, c("state_code", "state_name", "lat", "lng")]
}

# Function to get state metrics
get_state_metrics <- function() {
  brazil_states[, c("state_code", "state_name", "population", "area_km2", "gdp_billions", "hdi")]
}