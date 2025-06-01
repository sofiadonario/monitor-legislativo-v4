# ============================================================================
# GEOGRAPHIC ANALYSIS ENDPOINT - WEEK 6 REST API IMPLEMENTATION  
# ============================================================================
# 
# Geographic data analysis and statistics for Brazilian legislative monitoring
# Integrates with IBGE data and provides spatial analysis capabilities
# Optimized for academic research and policy analysis
# 
# Endpoints:
# - GET /api/v1/geographic/analysis - Main geographic analysis
# - GET /api/v1/geographic/states - State-level statistics
# - GET /api/v1/geographic/regions - Regional analysis
# - GET /api/v1/geographic/municipalities - Municipal data
# - GET /api/v1/geographic/ibge - IBGE integration data
# ============================================================================

cat("🗺️  Loading Geographic Analysis Endpoints - Week 6\n")

# Brazilian regions configuration
BRAZILIAN_REGIONS <- list(
  "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
  "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
  "Centro-Oeste" = c("GO", "MT", "MS", "DF"),
  "Sudeste" = c("ES", "MG", "RJ", "SP"),
  "Sul" = c("PR", "RS", "SC")
)

# State population data (approximate 2023 IBGE data)
STATE_POPULATION <- list(
  "SP" = 46649132, "MG" = 21411923, "RJ" = 17463349, "BA" = 14985284,
  "RS" = 11466630, "PR" = 11597484, "PE" = 9674793, "CE" = 9240580,
  "PA" = 8777124, "SC" = 7338473, "MA" = 7153262, "GO" = 7206589,
  "PB" = 4059905, "ES" = 4108508, "AM" = 4269995, "RN" = 3303953,
  "AL" = 3365351, "MT" = 3784239, "MS" = 2839188, "DF" = 3094325,
  "PI" = 3289290, "SE" = 2338474, "RO" = 1815278, "TO" = 1607363,
  "AC" = 906876, "RR" = 652713, "AP" = 877613
)

# Helper function to map states to regions
get_state_region <- function(estado) {
  for (region in names(BRAZILIAN_REGIONS)) {
    if (estado %in% BRAZILIAN_REGIONS[[region]]) {
      return(region)
    }
  }
  return("Indefinido")
}

# Calculate legislation density per capita
calculate_legislation_density <- function(document_count, population) {
  if (is.null(population) || population == 0) return(0)
  return(round((document_count / population) * 100000, 2))  # per 100k inhabitants
}

# Main geographic analysis endpoint
#' @get /api/v1/geographic/analysis
#' @param level:str Geographic level (state, region, municipality)
#' @param metric:str Analysis metric (count, density, growth, distribution)
#' @param estado:str Optional state filter for municipality-level analysis
#' @param year_start:int Start year for temporal analysis
#' @param year_end:int End year for temporal analysis  
#' @param format:str Response format (json, geojson)
#' @tag geographic
#' @serializer unboxedJSON
function(req, res, level = "state", metric = "count", estado = NULL, year_start = NULL, year_end = NULL, format = "json") {
  
  start_time <- Sys.time()
  
  # Validate parameters
  valid_levels <- c("state", "region", "municipality")
  valid_metrics <- c("count", "density", "growth", "distribution", "temporal")
  
  if (!(level %in% valid_levels)) {
    return(list(
      error = TRUE,
      message = paste("Nível geográfico inválido. Use:", paste(valid_levels, collapse = ", ")),
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  if (!(metric %in% valid_metrics)) {
    return(list(
      error = TRUE,
      message = paste("Métrica inválida. Use:", paste(valid_metrics, collapse = ", ")),
      code = 400,
      timestamp = Sys.time()
    ))
  }
  
  # Set response headers
  res$setHeader("Content-Language", "pt-BR")
  if (format == "geojson") {
    res$setHeader("Content-Type", "application/geo+json; charset=utf-8")
  }
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      if (level == "state") {
        # State-level analysis
        base_query <- "
          SELECT 
            estado,
            COUNT(*) as total_documentos,
            COUNT(DISTINCT municipio) as municipios_ativos,
            COUNT(DISTINCT species) as tipos_documentos,
            MIN(data_publicacao) as primeiro_documento,
            MAX(data_publicacao) as ultimo_documento,
            AVG(EXTRACT(YEAR FROM data_publicacao)) as ano_medio
          FROM documents 
          WHERE estado IS NOT NULL AND estado != ''
        "
        
        # Add year filters if provided
        if (!is.null(year_start)) {
          base_query <- paste(base_query, "AND EXTRACT(YEAR FROM data_publicacao) >=", as.numeric(year_start))
        }
        if (!is.null(year_end)) {
          base_query <- paste(base_query, "AND EXTRACT(YEAR FROM data_publicacao) <=", as.numeric(year_end))
        }
        
        base_query <- paste(base_query, "
          GROUP BY estado
          ORDER BY total_documentos DESC
        ")
        
        result <- dbGetQuery(secure_db_pool, base_query)
        
        # Add calculated metrics
        result$regiao <- sapply(result$estado, get_state_region)
        result$nome_estado <- sapply(result$estado, function(x) BRAZILIAN_STATES[[x]] %||% x)
        result$populacao_estimada <- sapply(result$estado, function(x) STATE_POPULATION[[x]] %||% 0)
        result$densidade_legislativa <- mapply(calculate_legislation_density, 
                                              result$total_documentos, 
                                              result$populacao_estimada)
        
        # Add percentages
        total_docs <- sum(result$total_documentos)
        result$percentual_nacional <- round((result$total_documentos / total_docs) * 100, 2)
        
      } else if (level == "region") {
        # Regional analysis
        query <- "
          SELECT 
            CASE 
              WHEN estado IN ('AC', 'AP', 'AM', 'PA', 'RO', 'RR', 'TO') THEN 'Norte'
              WHEN estado IN ('AL', 'BA', 'CE', 'MA', 'PB', 'PE', 'PI', 'RN', 'SE') THEN 'Nordeste'
              WHEN estado IN ('GO', 'MT', 'MS', 'DF') THEN 'Centro-Oeste'
              WHEN estado IN ('ES', 'MG', 'RJ', 'SP') THEN 'Sudeste'
              WHEN estado IN ('PR', 'RS', 'SC') THEN 'Sul'
              ELSE 'Indefinido'
            END as regiao,
            COUNT(*) as total_documentos,
            COUNT(DISTINCT estado) as estados_na_regiao,
            COUNT(DISTINCT municipio) as municipios_ativos,
            COUNT(DISTINCT species) as tipos_documentos,
            MIN(data_publicacao) as primeiro_documento,
            MAX(data_publicacao) as ultimo_documento
          FROM documents 
          WHERE estado IS NOT NULL AND estado != ''
        "
        
        # Add year filters
        if (!is.null(year_start)) {
          query <- paste(query, "AND EXTRACT(YEAR FROM data_publicacao) >=", as.numeric(year_start))
        }
        if (!is.null(year_end)) {
          query <- paste(query, "AND EXTRACT(YEAR FROM data_publicacao) <=", as.numeric(year_end))
        }
        
        query <- paste(query, "
          GROUP BY regiao
          ORDER BY total_documentos DESC
        ")
        
        result <- dbGetQuery(secure_db_pool, query)
        
        # Calculate regional population and density
        for (i in 1:nrow(result)) {
          region_states <- BRAZILIAN_REGIONS[[result$regiao[i]]]
          if (!is.null(region_states)) {
            region_pop <- sum(sapply(region_states, function(x) STATE_POPULATION[[x]] %||% 0))
            result$populacao_estimada[i] <- region_pop
            result$densidade_legislativa[i] <- calculate_legislation_density(result$total_documentos[i], region_pop)
          } else {
            result$populacao_estimada[i] <- 0
            result$densidade_legislativa[i] <- 0
          }
        }
        
      } else if (level == "municipality") {
        # Municipal analysis (limited to specific state if provided)
        query <- "
          SELECT 
            municipio,
            estado,
            COUNT(*) as total_documentos,
            COUNT(DISTINCT species) as tipos_documentos,
            MIN(data_publicacao) as primeiro_documento,
            MAX(data_publicacao) as ultimo_documento,
            ROUND(AVG(EXTRACT(YEAR FROM data_publicacao))) as ano_medio
          FROM documents 
          WHERE municipio IS NOT NULL AND municipio != ''
        "
        
        if (!is.null(estado)) {
          query <- paste(query, "AND estado =", shQuote(toupper(estado)))
        }
        
        # Add year filters
        if (!is.null(year_start)) {
          query <- paste(query, "AND EXTRACT(YEAR FROM data_publicacao) >=", as.numeric(year_start))
        }
        if (!is.null(year_end)) {
          query <- paste(query, "AND EXTRACT(YEAR FROM data_publicacao) <=", as.numeric(year_end))
        }
        
        query <- paste(query, "
          GROUP BY municipio, estado
          ORDER BY total_documentos DESC
          LIMIT 100
        ")
        
        result <- dbGetQuery(secure_db_pool, query)
        result$regiao <- sapply(result$estado, get_state_region)
        result$nome_estado <- sapply(result$estado, function(x) BRAZILIAN_STATES[[x]] %||% x)
      }
      
      # Calculate performance metrics
      processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
      
      # Format for GeoJSON if requested
      if (format == "geojson" && level == "state") {
        # Simplified GeoJSON structure (would need actual geographic boundaries)
        geojson_features <- list()
        for (i in 1:nrow(result)) {
          feature <- list(
            type = "Feature",
            properties = as.list(result[i, ]),
            geometry = list(
              type = "Point",
              coordinates = c(-45.0, -15.0)  # Placeholder coordinates
            )
          )
          geojson_features[[i]] <- feature
        }
        
        return(list(
          type = "FeatureCollection",
          features = geojson_features,
          metadata = list(
            level = level,
            metric = metric,
            total_features = length(geojson_features),
            processing_time_seconds = round(processing_time, 3),
            timestamp = Sys.time()
          )
        ))
      }
      
      return(list(
        error = FALSE,
        message = paste("Análise geográfica por", level),
        data = result,
        meta = list(
          level = level,
          metric = metric,
          total_records = nrow(result),
          filters = list(
            estado = estado,
            year_start = year_start,
            year_end = year_end
          ),
          performance = list(
            processing_time_seconds = round(processing_time, 3),
            source = "database"
          )
        ),
        timestamp = Sys.time()
      ))
      
    } else {
      # Fallback data for geographic analysis
      if (level == "state") {
        fallback_data <- data.frame(
          estado = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE"),
          nome_estado = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", "Paraná", "Santa Catarina", "Bahia", "Goiás", "Pernambuco", "Ceará"),
          regiao = c("Sudeste", "Sudeste", "Sudeste", "Sul", "Sul", "Sul", "Nordeste", "Centro-Oeste", "Nordeste", "Nordeste"),
          total_documentos = c(25000, 18000, 15000, 12000, 10000, 8000, 7000, 6000, 5000, 4000),
          municipios_ativos = c(450, 92, 320, 250, 200, 180, 280, 150, 120, 100),
          tipos_documentos = c(8, 7, 8, 6, 7, 6, 7, 5, 6, 5),
          densidade_legislativa = c(53.6, 103.2, 70.1, 104.6, 86.2, 109.1, 46.7, 83.3, 51.7, 43.3),
          percentual_nacional = c(18.5, 13.4, 11.2, 8.9, 7.4, 5.9, 5.2, 4.5, 3.7, 3.0),
          stringsAsFactors = FALSE
        )
      } else if (level == "region") {
        fallback_data <- data.frame(
          regiao = c("Sudeste", "Sul", "Nordeste", "Centro-Oeste", "Norte"),
          total_documentos = c(58000, 30000, 28000, 12000, 6000),
          estados_na_regiao = c(4, 3, 9, 4, 7),
          municipios_ativos = c(862, 630, 1200, 380, 250),
          tipos_documentos = c(10, 9, 8, 7, 6),
          densidade_legislativa = c(65.4, 95.2, 49.1, 74.8, 33.2),
          stringsAsFactors = FALSE
        )
      } else {
        fallback_data <- data.frame(
          municipio = c("São Paulo", "Rio de Janeiro", "Belo Horizonte", "Porto Alegre", "Curitiba", "Salvador", "Brasília", "Recife", "Goiânia", "Fortaleza"),
          estado = c("SP", "RJ", "MG", "RS", "PR", "BA", "DF", "PE", "GO", "CE"),
          regiao = c("Sudeste", "Sudeste", "Sudeste", "Sul", "Sul", "Nordeste", "Centro-Oeste", "Nordeste", "Centro-Oeste", "Nordeste"),
          total_documentos = c(3500, 2800, 2200, 1800, 1500, 1300, 1200, 1100, 900, 800),
          tipos_documentos = c(8, 7, 7, 6, 6, 6, 5, 5, 5, 4),
          stringsAsFactors = FALSE
        )
      }
      
      return(list(
        error = FALSE,
        message = paste("Análise geográfica por", level, "(dados de exemplo)"),
        data = fallback_data,
        meta = list(
          level = level,
          metric = metric,
          total_records = nrow(fallback_data),
          source = "fallback",
          warning = "Dados de exemplo"
        ),
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = "Erro na análise geográfica",
      details = "Erro interno ao processar dados geográficos",
      code = 500,
      timestamp = Sys.time(),
      debug = if (Sys.getenv("DEBUG") == "true") e$message else NULL
    ))
  })
}

# IBGE integration endpoint
#' @get /api/v1/geographic/ibge
#' @param data_type:str Type of IBGE data (population, area, gdp)
#' @param level:str Geographic level (state, municipality)
#' @param codigo_ibge:str Optional IBGE code filter
#' @tag geographic
#' @serializer unboxedJSON
function(req, res, data_type = "population", level = "state", codigo_ibge = NULL) {
  
  # IBGE data integration (placeholder implementation)
  # In production, this would connect to IBGE APIs or local IBGE database
  
  if (data_type == "population" && level == "state") {
    ibge_data <- data.frame(
      codigo_ibge = c(35, 33, 31, 43, 41, 42, 29, 52, 26, 23),
      estado = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE"),
      nome_estado = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", "Paraná", "Santa Catarina", "Bahia", "Goiás", "Pernambuco", "Ceará"),
      populacao_2023 = c(46649132, 17463349, 21411923, 11466630, 11597484, 7338473, 14985284, 7206589, 9674793, 9240580),
      area_km2 = c(248219, 43777, 586521, 281707, 199307, 95737, 564733, 340112, 98068, 148894),
      densidade_demografica = c(188.0, 398.9, 36.5, 40.7, 58.2, 76.7, 26.5, 21.2, 98.7, 62.1),
      pib_milhoes_reais = c(2719000, 753887, 711617, 470891, 487557, 295000, 305319, 224136, 200335, 171810),
      stringsAsFactors = FALSE
    )
    
    return(list(
      error = FALSE,
      message = "Dados IBGE integrados",
      data = ibge_data,
      meta = list(
        data_type = data_type,
        level = level,
        source = "IBGE",
        reference_year = 2023,
        total_records = nrow(ibge_data)
      ),
      timestamp = Sys.time()
    ))
  } else {
    return(list(
      error = FALSE,
      message = "Integração IBGE em desenvolvimento",
      data = list(),
      meta = list(
        data_type = data_type,
        level = level,
        status = "placeholder"
      ),
      timestamp = Sys.time()
    ))
  }
}

# Temporal analysis endpoint
#' @get /api/v1/geographic/temporal
#' @param level:str Geographic level (state, region)
#' @param period:str Time period (yearly, monthly)
#' @param year_start:int Start year (default: 2018)
#' @param year_end:int End year (default: current year)
#' @tag geographic
#' @serializer unboxedJSON
function(req, res, level = "state", period = "yearly", year_start = 2018, year_end = NULL) {
  
  if (is.null(year_end)) {
    year_end <- as.numeric(format(Sys.Date(), "%Y"))
  }
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      if (level == "state" && period == "yearly") {
        query <- "
          SELECT 
            estado,
            EXTRACT(YEAR FROM data_publicacao) as ano,
            COUNT(*) as total_documentos,
            COUNT(DISTINCT species) as tipos_diferentes
          FROM documents 
          WHERE estado IS NOT NULL 
            AND EXTRACT(YEAR FROM data_publicacao) BETWEEN $1 AND $2
          GROUP BY estado, EXTRACT(YEAR FROM data_publicacao)
          ORDER BY estado, ano
        "
        
        result <- dbGetQuery(secure_db_pool, query, list(year_start, year_end))
        
        # Add state names and regions
        result$nome_estado <- sapply(result$estado, function(x) BRAZILIAN_STATES[[x]] %||% x)
        result$regiao <- sapply(result$estado, get_state_region)
        
      } else {
        # Fallback for other combinations
        result <- data.frame(
          message = "Combinação de parâmetros não implementada",
          level = level,
          period = period
        )
      }
      
      return(list(
        error = FALSE,
        message = "Análise temporal geográfica",
        data = result,
        meta = list(
          level = level,
          period = period,
          year_range = c(year_start, year_end),
          total_records = nrow(result)
        ),
        timestamp = Sys.time()
      ))
      
    } else {
      # Fallback temporal data
      years <- year_start:year_end
      states <- c("SP", "RJ", "MG", "RS", "PR")
      
      temporal_data <- expand.grid(estado = states, ano = years)
      temporal_data$total_documentos <- sample(100:2000, nrow(temporal_data))
      temporal_data$tipos_diferentes <- sample(3:8, nrow(temporal_data), replace = TRUE)
      temporal_data$nome_estado <- sapply(temporal_data$estado, function(x) BRAZILIAN_STATES[[x]] %||% x)
      temporal_data$regiao <- sapply(temporal_data$estado, get_state_region)
      
      return(list(
        error = FALSE,
        message = "Análise temporal (dados de exemplo)",
        data = temporal_data,
        meta = list(
          level = level,
          period = period,
          year_range = c(year_start, year_end),
          source = "fallback"
        ),
        timestamp = Sys.time()
      ))
    }
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = "Erro na análise temporal geográfica",
      code = 500,
      timestamp = Sys.time()
    ))
  })
}

cat("✅ Geographic Analysis Endpoints loaded successfully\n")