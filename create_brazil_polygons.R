# Create simplified Brazilian state polygons for choropleth
# This creates basic rectangular approximations for each state

get_brazil_state_polygons <- function() {
  # Simplified state boundaries (rectangles approximating actual shapes)
  # In production, you'd use actual GeoJSON boundaries
  
  state_polygons <- list(
    # Amazon region (North)
    AC = list(lon = c(-74, -66.5, -66.5, -74, -74), lat = c(-11.5, -11.5, -7, -7, -11.5)),
    AP = list(lon = c(-54.8, -49.8, -49.8, -54.8, -54.8), lat = c(4.5, 4.5, -1.2, -1.2, 4.5)),
    AM = list(lon = c(-74, -56, -56, -74, -74), lat = c(-2, -2, -10, -10, -2)),
    PA = list(lon = c(-58, -46, -46, -58, -58), lat = c(2.5, 2.5, -10, -10, 2.5)),
    RO = list(lon = c(-66, -60, -60, -66, -66), lat = c(-7.5, -7.5, -13.5, -13.5, -7.5)),
    RR = list(lon = c(-64.8, -58.8, -58.8, -64.8, -64.8), lat = c(5.3, 5.3, -1, -1, 5.3)),
    TO = list(lon = c(-51, -45.5, -45.5, -51, -51), lat = c(-5, -5, -11.8, -11.8, -5)),
    
    # Northeast region
    AL = list(lon = c(-38, -35, -35, -38, -38), lat = c(-8.8, -8.8, -10.5, -10.5, -8.8)),
    BA = list(lon = c(-47.8, -38, -38, -47.8, -47.8), lat = c(-9, -9, -18.3, -18.3, -9)),
    CE = list(lon = c(-41.4, -37.2, -37.2, -41.4, -41.4), lat = c(-2.8, -2.8, -7.9, -7.9, -2.8)),
    MA = list(lon = c(-48.5, -41.8, -41.8, -48.5, -48.5), lat = c(-1.2, -1.2, -10, -10, -1.2)),
    PB = list(lon = c(-38.8, -34.8, -34.8, -38.8, -38.8), lat = c(-6, -6, -8.2, -8.2, -6)),
    PE = list(lon = c(-41.3, -34.8, -34.8, -41.3, -41.3), lat = c(-7.3, -7.3, -9.5, -9.5, -7.3)),
    PI = list(lon = c(-46, -40.1, -40.1, -46, -46), lat = c(-2.7, -2.7, -10.9, -10.9, -2.7)),
    RN = list(lon = c(-38.5, -34.9, -34.9, -38.5, -38.5), lat = c(-4.8, -4.8, -6.9, -6.9, -4.8)),
    SE = list(lon = c(-38.2, -36.4, -36.4, -38.2, -38.2), lat = c(-10.2, -10.2, -11.6, -11.6, -10.2)),
    
    # Central-West region
    DF = list(lon = c(-48.3, -47.2, -47.2, -48.3, -48.3), lat = c(-15.5, -15.5, -16.1, -16.1, -15.5)),
    GO = list(lon = c(-53.2, -45.9, -45.9, -53.2, -53.2), lat = c(-12.4, -12.4, -19.5, -19.5, -12.4)),
    MT = list(lon = c(-66, -50.2, -50.2, -66, -66), lat = c(-7.3, -7.3, -18.1, -18.1, -7.3)),
    MS = list(lon = c(-58, -50.1, -50.1, -58, -58), lat = c(-17.9, -17.9, -24.1, -24.1, -17.9)),
    
    # Southeast region  
    ES = list(lon = c(-41.9, -39.7, -39.7, -41.9, -41.9), lat = c(-17.9, -17.9, -21.3, -21.3, -17.9)),
    MG = list(lon = c(-51.1, -39.8, -39.8, -51.1, -51.1), lat = c(-14.2, -14.2, -22.9, -22.9, -14.2)),
    RJ = list(lon = c(-45, -40.9, -40.9, -45, -45), lat = c(-20.7, -20.7, -23.4, -23.4, -20.7)),
    SP = list(lon = c(-53.1, -44.2, -44.2, -53.1, -53.1), lat = c(-19.8, -19.8, -25.3, -25.3, -19.8)),
    
    # South region
    PR = list(lon = c(-54.6, -48.1, -48.1, -54.6, -54.6), lat = c(-22.5, -22.5, -26.7, -26.7, -22.5)),
    RS = list(lon = c(-57.6, -49.7, -49.7, -57.6, -57.6), lat = c(-27.1, -27.1, -33.8, -33.8, -27.1)),
    SC = list(lon = c(-53.8, -48.3, -48.3, -53.8, -53.8), lat = c(-25.9, -25.9, -29.4, -29.4, -25.9))
  )
  
  return(state_polygons)
}

cat("🗺️ Brazilian state polygon definitions created\n")
cat("📍 Covers all 27 states with simplified rectangular boundaries\n")