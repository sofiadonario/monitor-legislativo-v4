# Inline Maps Fallback
# This creates map functions directly without requiring external files

# Create inline map UI function
create_inline_maps_ui <- function() {
  tabItem(
    tabName = "maps",
    fluidRow(
      box(
        title = "Interactive Document Distribution Maps",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        # Simple message for now
        h4("Map Visualization"),
        p("The maps module is currently being loaded..."),
        
        # Basic controls
        fluidRow(
          column(
            width = 6,
            selectInput(
              "map_type_inline",
              "Map Type:",
              choices = c("State Distribution" = "state"),
              selected = "state"
            )
          ),
          column(
            width = 6,
            selectInput(
              "map_metric_inline",
              "Display Metric:",
              choices = c("Document Count" = "count"),
              selected = "count"
            )
          )
        ),
        
        # Placeholder for map
        plotlyOutput("inline_brazil_map", height = "400px"),
        
        # Info box
        br(),
        infoBox(
          "Status",
          "Basic map functionality active",
          icon = icon("map"),
          color = "blue",
          width = 12
        )
      )
    )
  )
}

# Create inline Brazilian states data
brazil_states_inline <- data.frame(
  state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                 "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                 "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
  state_name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
                 "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                 "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
                 "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro",
                 "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima", 
                 "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
  lat = c(-9.0, -9.7, 0.9, -5.1, -13.3, -5.2, -15.8, -20.3, -16.7, -3.7,
          -15.6, -21.2, -19.9, -4.3, -7.2, -25.4, -8.0, -7.4, -22.9, -5.8,
          -30.0, -10.9, 2.8, -27.6, -23.6, -10.6, -10.3),
  lng = c(-70.5, -36.7, -51.7, -63.1, -41.7, -38.9, -47.9, -40.8, -49.3, -45.1,
          -56.1, -54.6, -43.9, -52.7, -36.8, -49.3, -35.0, -42.1, -43.2, -36.6,
          -51.2, -62.8, -60.7, -48.5, -46.6, -37.3, -48.4),
  stringsAsFactors = FALSE
)

# Export functions to global environment
assign("create_inline_maps_ui", create_inline_maps_ui, envir = .GlobalEnv)
assign("brazil_states_inline", brazil_states_inline, envir = .GlobalEnv)
assign("INLINE_MAPS_AVAILABLE", TRUE, envir = .GlobalEnv)

cat("✅ Inline maps fallback loaded\n")