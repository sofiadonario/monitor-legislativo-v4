#' @title Funções Geográficas do Monitor Legislativo
#' @description Funções para análise geográfica e espacial de dados legislativos brasileiros
#' @author Monitor Legislativo Research Team
#' @importFrom dplyr tibble bind_rows filter arrange select mutate group_by summarise count
#' @importFrom purrr map_dfr map_chr map_dbl safely
#' @importFrom sf st_read st_as_sf st_transform st_centroid st_area
#' @importFrom ggplot2 ggplot aes geom_sf geom_point scale_fill_viridis_c theme_minimal labs
#' @importFrom cli cli_alert_info cli_alert_success cli_alert_error
#' @importFrom glue glue

#' Análise geográfica de documentos legislativos
#'
#' @description
#' Realiza análise espacial dos documentos legislativos, incluindo distribuição
#' por estados e municípios, densidade legislativa e padrões geográficos.
#'
#' @param query String. Termo de busca para filtrar documentos (opcional).
#' @param geographic_level String. Nível de análise: "state", "municipality", "region".
#' @param aggregation String. Tipo de agregação: "count", "density", "coverage".
#' @param time_period String. Período temporal: "all", "year", "month".
#' @param include_geometry Logical. Incluir geometrias espaciais para mapping.
#' @param filter_empty Logical. Remover áreas sem documentos.
#' @param min_documents Integer. Número mínimo de documentos para incluir na análise.
#' 
#' @return tibble com análise geográfica e opcionalmente geometrias SF.
#' 
#' @examples
#' \dontrun{
#' # Análise por estados
#' geo_analysis <- ml_geographic_analysis(
#'   query = "transporte público",
#'   geographic_level = "state",
#'   aggregation = "count"
#' )
#' 
#' # Análise municipal com geometrias
#' municipal_analysis <- ml_geographic_analysis(
#'   geographic_level = "municipality",
#'   include_geometry = TRUE,
#'   min_documents = 5
#' )
#' 
#' # Análise de densidade regional
#' regional_density <- ml_geographic_analysis(
#'   geographic_level = "region",
#'   aggregation = "density",
#'   time_period = "year"
#' )
#' }
#' 
#' @export
ml_geographic_analysis <- function(query = NULL,
                                  geographic_level = "state",
                                  aggregation = "count",
                                  time_period = "all",
                                  include_geometry = FALSE,
                                  filter_empty = TRUE,
                                  min_documents = 1) {
  
  # Validar parâmetros
  if (!geographic_level %in% c("state", "municipality", "region")) {
    stop("geographic_level deve ser um de: 'state', 'municipality', 'region'")
  }
  
  if (!aggregation %in% c("count", "density", "coverage")) {
    stop("aggregation deve ser um de: 'count', 'density', 'coverage'")
  }
  
  if (!time_period %in% c("all", "year", "month")) {
    stop("time_period deve ser um de: 'all', 'year', 'month'")
  }
  
  min_documents <- max(1, as.integer(min_documents))
  
  cli_alert_info(glue("Iniciando análise geográfica: nível {geographic_level}, agregação {aggregation}"))
  
  # Preparar parâmetros da requisição
  request_body <- list(
    query = query,
    geographic_level = geographic_level,
    aggregation = aggregation,
    time_period = time_period,
    include_geometry = include_geometry,
    filter_empty = filter_empty,
    min_documents = min_documents
  )
  
  tryCatch({
    result <- .ml_api_call("POST", "/geographic/analysis", body = request_body)
    
    if (isTRUE(is.null(result)) || !result$success) {
      stop("Falha na análise geográfica: ", result$message %||% "Erro desconhecido")
    }
    
    geo_data <- result$data %||% list()
    meta <- result$meta %||% list()
    
    if (length(geo_data) == 0) {
      cli_alert_info("Nenhum dado geográfico encontrado")
      return(tibble())
    }
    
    # Processar dados geográficos
    geo_df <- map_dfr(geo_data, function(item) {
      base_data <- tibble(
        id = as.character(item$id %||% ""),
        name = as.character(item$name %||% ""),
        code = as.character(item$code %||% ""),
        level = geographic_level,
        document_count = as.integer(item$document_count %||% 0),
        population = as.integer(item$population %||% 0),
        area_km2 = as.numeric(item$area_km2 %||% 0)
      )
      
      # Adicionar métricas específicas do tipo de agregação
      if (aggregation == "density") {
        base_data$documents_per_1000_inhabitants <- as.numeric(item$density_per_1000 %||% 0)
        base_data$documents_per_km2 <- as.numeric(item$density_per_km2 %||% 0)
      } else if (aggregation == "coverage") {
        base_data$coverage_percentage <- as.numeric(item$coverage_percentage %||% 0)
        base_data$categories_covered <- as.integer(item$categories_covered %||% 0)
      }
      
      # Adicionar dados temporais se disponíveis
      if (time_period != "all" && !is.null(item$temporal_data)) {
        base_data$period <- as.character(item$temporal_data$period %||% "")
        base_data$period_start <- as.character(item$temporal_data$start_date %||% "")
        base_data$period_end <- as.character(item$temporal_data$end_date %||% "")
      }
      
      return(base_data)
    })
    
    # Processar geometrias se solicitado
    if (include_geometry && !is.null(result$geometries)) {
      tryCatch({
        # Criar objeto SF com geometrias
        geometries_data <- result$geometries
        
        # Adicionar geometrias ao dataframe
        if (length(geometries_data) > 0) {
          geo_sf <- st_as_sf(geo_df, wkt = "geometry")
          geo_df <- geo_sf
        }
        
      }, error = function(e) {
        cli_alert_error(glue("Erro ao processar geometrias: {e$message}"))
        cli_alert_info("Retornando dados sem geometrias")
      })
    }
    
    # Filtrar por número mínimo de documentos
    if (min_documents > 1) {
      original_count <- nrow(geo_df)
      geo_df <- geo_df %>% filter(document_count >= min_documents)
      cli_alert_info(glue("Filtrado {original_count - nrow(geo_df)} áreas com menos de {min_documents} documentos"))
    }
    
    # Adicionar metadados
    attr(geo_df, "geographic_meta") <- meta
    attr(geo_df, "analysis_params") <- list(
      geographic_level = geographic_level,
      aggregation = aggregation,
      time_period = time_period,
      include_geometry = include_geometry,
      min_documents = min_documents,
      query = query
    )
    attr(geo_df, "analysis_date") <- Sys.time()
    
    cli_alert_success(glue("Análise geográfica concluída: {nrow(geo_df)} áreas analisadas"))
    
    return(geo_df)
    
  }, error = function(e) {
    stop("Erro na análise geográfica: ", e$message)
  })
}

#' Obter lista de estados brasileiros
#'
#' @description
#' Recupera informações sobre todos os estados brasileiros com estatísticas
#' de documentos legislativos disponíveis.
#'
#' @param include_stats Logical. Incluir estatísticas de documentos.
#' @param include_geometry Logical. Incluir geometrias dos estados.
#' @param order_by String. Critério de ordenação: "name", "code", "document_count", "population".
#' 
#' @return tibble com informações dos estados brasileiros.
#' 
#' @examples
#' \dontrun{
#' # Lista básica de estados
#' states <- ml_get_states()
#' 
#' # Estados com estatísticas
#' states_with_stats <- ml_get_states(include_stats = TRUE)
#' 
#' # Estados com geometrias para mapping
#' states_geo <- ml_get_states(
#'   include_stats = TRUE,
#'   include_geometry = TRUE,
#'   order_by = "document_count"
#' )
#' }
#' 
#' @export
ml_get_states <- function(include_stats = TRUE,
                         include_geometry = FALSE,
                         order_by = "name") {
  
  if (!order_by %in% c("name", "code", "document_count", "population")) {
    stop("order_by deve ser um de: 'name', 'code', 'document_count', 'population'")
  }
  
  # Construir parâmetros
  params <- list(
    include_stats = include_stats,
    include_geometry = include_geometry,
    order_by = order_by
  )
  
  # Construir URL
  query_string <- paste(
    names(params),
    vapply(params, function(x) URLencode(as.character(x)), character(1)),
    sep = "=",
    collapse = "&"
  )
  
  endpoint <- glue("/geographic/states?{query_string}")
  
  tryCatch({
    result <- .ml_api_call("GET", endpoint)
    
    if (isTRUE(is.null(result)) || !result$success) {
      stop("Erro ao obter estados: ", result$message %||% "Erro desconhecido")
    }
    
    states_data <- result$data %||% list()
    
    if (length(states_data) == 0) {
      return(tibble(
        code = character(0),
        name = character(0),
        region = character(0)
      ))
    }
    
    # Processar dados dos estados
    states_df <- map_dfr(states_data, function(state) {
      base_data <- tibble(
        code = as.character(state$code %||% ""),
        name = as.character(state$name %||% ""),
        region = as.character(state$region %||% ""),
        capital = as.character(state$capital %||% ""),
        population = as.integer(state$population %||% 0),
        area_km2 = as.numeric(state$area_km2 %||% 0)
      )
      
      # Adicionar estatísticas se solicitadas
      if (include_stats && !is.null(state$stats)) {
        base_data$document_count <- as.integer(state$stats$document_count %||% 0)
        base_data$municipality_count <- as.integer(state$stats$municipality_count %||% 0)
        base_data$categories_count <- as.integer(state$stats$categories_count %||% 0)
        base_data$documents_per_1000_inhabitants <- as.numeric(state$stats$documents_per_1000 %||% 0)
        base_data$last_document_date <- as.character(state$stats$last_document_date %||% "")
      }
      
      return(base_data)
    })
    
    # Processar geometrias se solicitado
    if (include_geometry && !is.null(result$geometries)) {
      tryCatch({
        # Processar geometrias (implementação específica depende do formato)
        cli_alert_info("Processando geometrias dos estados...")
        # Aqui seria implementada a lógica específica para geometrias
        
      }, error = function(e) {
        cli_alert_error(glue("Erro ao processar geometrias: {e$message}"))
      })
    }
    
    # Adicionar metadados
    attr(states_df, "include_stats") <- include_stats
    attr(states_df, "include_geometry") <- include_geometry
    attr(states_df, "order_by") <- order_by
    attr(states_df, "retrieved_at") <- Sys.time()
    
    return(states_df)
    
  }, error = function(e) {
    stop("Erro ao obter estados: ", e$message)
  })
}

#' Obter municípios por estado ou região
#'
#' @description
#' Recupera informações sobre municípios brasileiros com opções de filtro
#' por estado, região ou padrão de busca.
#'
#' @param state String. Sigla do estado (opcional).
#' @param region String. Nome da região (opcional).
#' @param search_pattern String. Padrão de busca no nome do município.
#' @param min_population Integer. População mínima do município.
#' @param include_stats Logical. Incluir estatísticas de documentos.
#' @param limit Integer. Número máximo de municípios a retornar.
#' @param order_by String. Critério de ordenação.
#' 
#' @return tibble com informações dos municípios.
#' 
#' @examples
#' \dontrun{
#' # Municípios de São Paulo
#' sp_municipalities <- ml_get_municipalities(state = "SP")
#' 
#' # Municípios da região Sudeste com estatísticas
#' southeast_municipalities <- ml_get_municipalities(
#'   region = "Sudeste",
#'   include_stats = TRUE,
#'   min_population = 100000
#' )
#' 
#' # Buscar municípios por nome
#' santos_cities <- ml_get_municipalities(
#'   search_pattern = "Santos",
#'   include_stats = TRUE
#' )
#' 
#' # Maiores municípios por população
#' big_cities <- ml_get_municipalities(
#'   min_population = 500000,
#'   order_by = "population",
#'   limit = 50
#' )
#' }
#' 
#' @export
ml_get_municipalities <- function(state = NULL,
                                 region = NULL,
                                 search_pattern = NULL,
                                 min_population = NULL,
                                 include_stats = TRUE,
                                 limit = 1000,
                                 order_by = "name") {
  
  if (!order_by %in% c("name", "population", "document_count", "state")) {
    stop("order_by deve ser um de: 'name', 'population', 'document_count', 'state'")
  }
  
  limit <- max(1, min(as.integer(limit), 5000))
  
  # Construir parâmetros
  params <- list(
    include_stats = include_stats,
    limit = limit,
    order_by = order_by
  )
  
  if (!is.null(state)) {
    params$state <- toupper(state)
  }
  
  if (!is.null(region)) {
    params$region <- region
  }
  
  if (!is.null(search_pattern)) {
    params$search_pattern <- search_pattern
  }
  
  if (!is.null(min_population)) {
    params$min_population <- as.integer(min_population)
  }
  
  # Construir URL
  query_string <- paste(
    names(params),
    vapply(params, function(x) URLencode(as.character(x)), character(1)),
    sep = "=",
    collapse = "&"
  )
  
  endpoint <- glue("/geographic/municipalities?{query_string}")
  
  tryCatch({
    result <- .ml_api_call("GET", endpoint)
    
    if (isTRUE(is.null(result)) || !result$success) {
      stop("Erro ao obter municípios: ", result$message %||% "Erro desconhecido")
    }
    
    municipalities_data <- result$data %||% list()
    meta <- result$meta %||% list()
    
    if (length(municipalities_data) == 0) {
      return(tibble(
        code = character(0),
        name = character(0),
        state = character(0),
        region = character(0)
      ))
    }
    
    # Processar dados dos municípios
    municipalities_df <- map_dfr(municipalities_data, function(municipality) {
      base_data <- tibble(
        code = as.character(municipality$code %||% ""),
        name = as.character(municipality$name %||% ""),
        state = as.character(municipality$state %||% ""),
        state_code = as.character(municipality$state_code %||% ""),
        region = as.character(municipality$region %||% ""),
        population = as.integer(municipality$population %||% 0),
        area_km2 = as.numeric(municipality$area_km2 %||% 0),
        latitude = as.numeric(municipality$latitude %||% 0),
        longitude = as.numeric(municipality$longitude %||% 0)
      )
      
      # Adicionar estatísticas se solicitadas
      if (include_stats && !is.null(municipality$stats)) {
        base_data$document_count <- as.integer(municipality$stats$document_count %||% 0)
        base_data$categories_count <- as.integer(municipality$stats$categories_count %||% 0)
        base_data$documents_per_1000_inhabitants <- as.numeric(municipality$stats$documents_per_1000 %||% 0)
        base_data$first_document_date <- as.character(municipality$stats$first_document_date %||% "")
        base_data$last_document_date <- as.character(municipality$stats$last_document_date %||% "")
      }
      
      return(base_data)
    })
    
    # Adicionar metadados
    attr(municipalities_df, "search_params") <- list(
      state = state,
      region = region,
      search_pattern = search_pattern,
      min_population = min_population,
      include_stats = include_stats,
      limit = limit,
      order_by = order_by
    )
    attr(municipalities_df, "total_found") <- meta$total_count %||% nrow(municipalities_df)
    attr(municipalities_df, "retrieved_at") <- Sys.time()
    
    return(municipalities_df)
    
  }, error = function(e) {
    stop("Erro ao obter municípios: ", e$message)
  })
}

#' Criar mapa coroplético de dados legislativos
#'
#' @description
#' Gera mapa coroplético (choropleth) para visualização da distribuição
#' geográfica de documentos legislativos por estado ou município.
#'
#' @param data tibble. Dados geográficos com estatísticas (resultado de ml_geographic_analysis).
#' @param fill_variable String. Variável para colorir o mapa.
#' @param geographic_level String. Nível geográfico: "state" ou "municipality".
#' @param color_scale String. Escala de cores: "viridis", "plasma", "inferno", "magma".
#' @param title String. Título do mapa.
#' @param subtitle String. Subtítulo do mapa.
#' @param legend_title String. Título da legenda.
#' @param save_path String. Caminho para salvar o mapa (opcional).
#' 
#' @return ggplot object com o mapa coroplético.
#' 
#' @examples
#' \dontrun{
#' # Obter dados geográficos
#' geo_data <- ml_geographic_analysis(
#'   geographic_level = "state",
#'   include_geometry = TRUE
#' )
#' 
#' # Criar mapa coroplético
#' map_plot <- ml_create_choropleth_map(
#'   data = geo_data,
#'   fill_variable = "document_count",
#'   title = "Distribuição de Documentos Legislativos por Estado",
#'   legend_title = "Número de Documentos"
#' )
#' 
#' print(map_plot)
#' 
#' # Salvar mapa
#' ml_create_choropleth_map(
#'   data = geo_data,
#'   fill_variable = "documents_per_1000_inhabitants",
#'   title = "Densidade Legislativa por Estado",
#'   save_path = "mapa_densidade.png"
#' )
#' }
#' 
#' @export
ml_create_choropleth_map <- function(data,
                                    fill_variable,
                                    geographic_level = "state",
                                    color_scale = "viridis",
                                    title = "Mapa de Documentos Legislativos",
                                    subtitle = NULL,
                                    legend_title = fill_variable,
                                    save_path = NULL) {
  
  # Verificar se ggplot2 está disponível
  if (!requireNamespace("ggplot2", quietly = TRUE)) {
    stop("Pacote ggplot2 é necessário para criar mapas")
  }
  
  # Verificar se sf está disponível
  if (!requireNamespace("sf", quietly = TRUE)) {
    stop("Pacote sf é necessário para dados geográficos")
  }
  
  # Verificar se dados têm geometrias
  if (!inherits(data, "sf")) {
    stop("Dados devem incluir geometrias (use include_geometry = TRUE)")
  }
  
  # Verificar se variável existe
  if (!fill_variable %in% names(data)) {
    stop(glue("Variável '{fill_variable}' não encontrada nos dados"))
  }
  
  # Verificar escala de cores
  if (!color_scale %in% c("viridis", "plasma", "inferno", "magma")) {
    color_scale <- "viridis"
  }
  
  cli_alert_info("Criando mapa coroplético...")
  
  tryCatch({
    # Criar mapa base
    map_plot <- ggplot(data) +
      geom_sf(aes(fill = !!sym(fill_variable)), color = "white", size = 0.2) +
      theme_minimal() +
      theme(
        axis.text = element_blank(),
        axis.ticks = element_blank(),
        panel.grid = element_blank(),
        panel.background = element_rect(fill = "white"),
        plot.title = element_text(hjust = 0.5, size = 14, face = "bold"),
        plot.subtitle = element_text(hjust = 0.5, size = 12),
        legend.position = "bottom",
        legend.key.width = unit(1.5, "cm")
      ) +
      labs(
        title = title,
        subtitle = subtitle,
        fill = legend_title,
        caption = glue("Dados: Monitor Legislativo | Gerado em {Sys.Date()}")
      )
    
    # Adicionar escala de cores
    if (color_scale == "viridis") {
      map_plot <- map_plot + scale_fill_viridis_c(option = "viridis", direction = 1)
    } else if (color_scale == "plasma") {
      map_plot <- map_plot + scale_fill_viridis_c(option = "plasma", direction = 1)
    } else if (color_scale == "inferno") {
      map_plot <- map_plot + scale_fill_viridis_c(option = "inferno", direction = 1)
    } else if (color_scale == "magma") {
      map_plot <- map_plot + scale_fill_viridis_c(option = "magma", direction = 1)
    }
    
    # Ajustar coordenadas para o Brasil
    if (geographic_level == "state") {
      map_plot <- map_plot + coord_sf(xlim = c(-75, -30), ylim = c(-35, 10))
    }
    
    # Salvar se caminho fornecido
    if (!is.null(save_path)) {
      ggsave(save_path, map_plot, width = 12, height = 8, dpi = 300)
      cli_alert_success(glue("Mapa salvo em: {save_path}"))
    }
    
    cli_alert_success("Mapa coroplético criado com sucesso")
    
    return(map_plot)
    
  }, error = function(e) {
    stop("Erro ao criar mapa: ", e$message)
  })
}

#' Análise de clusters geográficos
#'
#' @description
#' Identifica clusters geográficos de atividade legislativa usando algoritmos
#' de clusterização espacial.
#'
#' @param data tibble. Dados geográficos com coordenadas.
#' @param cluster_variable String. Variável para clusterização.
#' @param method String. Método de clusterização: "kmeans", "hierarchical", "dbscan".
#' @param n_clusters Integer. Número de clusters (para kmeans e hierarchical).
#' @param min_points Integer. Mínimo de pontos por cluster (para DBSCAN).
#' 
#' @return tibble com dados originais e identificação de clusters.
#' 
#' @examples
#' \dontrun{
#' # Obter dados municipais
#' municipalities <- ml_get_municipalities(include_stats = TRUE)
#' 
#' # Análise de clusters por densidade legislativa
#' clusters <- ml_geographic_clustering(
#'   data = municipalities,
#'   cluster_variable = "documents_per_1000_inhabitants",
#'   method = "kmeans",
#'   n_clusters = 5
#' )
#' 
#' # Ver estatísticas dos clusters
#' cluster_summary <- clusters %>%
#'   group_by(cluster) %>%
#'   summarise(
#'     municipalities = n(),
#'     avg_documents = mean(document_count),
#'     avg_density = mean(documents_per_1000_inhabitants)
#'   )
#' }
#' 
#' @export
ml_geographic_clustering <- function(data,
                                    cluster_variable,
                                    method = "kmeans",
                                    n_clusters = 5,
                                    min_points = 5) {
  
  if (!method %in% c("kmeans", "hierarchical", "dbscan")) {
    stop("method deve ser um de: 'kmeans', 'hierarchical', 'dbscan'")
  }
  
  if (!cluster_variable %in% names(data)) {
    stop(glue("Variável '{cluster_variable}' não encontrada nos dados"))
  }
  
  # Verificar se existem coordenadas
  if (!all(c("latitude", "longitude") %in% names(data))) {
    stop("Dados devem conter colunas 'latitude' e 'longitude'")
  }
  
  # Remover linhas com valores ausentes
  clean_data <- data %>%
    filter(
      !is.na(!!sym(cluster_variable)),
      !is.na(latitude),
      !is.na(longitude),
      latitude != 0,
      longitude != 0
    )
  
  if (nrow(clean_data) == 0) {
    stop("Nenhum dado válido para clusterização")
  }
  
  cli_alert_info(glue("Executando clusterização {method} com {nrow(clean_data)} pontos"))
  
  # Preparar dados para clusterização
  cluster_data <- clean_data %>%
    select(!!sym(cluster_variable), latitude, longitude) %>%
    scale() %>%
    as.data.frame()
  
  tryCatch({
    # Executar clusterização
    if (method == "kmeans") {
      if (n_clusters >= nrow(clean_data)) {
        n_clusters <- max(2, floor(nrow(clean_data) / 2))
        cli_alert_info(glue("Ajustando número de clusters para {n_clusters}"))
      }
      
      set.seed(123) # Para reprodutibilidade
      cluster_result <- kmeans(cluster_data, centers = n_clusters, nstart = 25)
      clusters <- cluster_result$cluster
      
    } else if (method == "hierarchical") {
      dist_matrix <- dist(cluster_data)
      hc_result <- hclust(dist_matrix, method = "ward.D2")
      clusters <- cutree(hc_result, k = n_clusters)
      
    } else if (method == "dbscan") {
      if (!requireNamespace("dbscan", quietly = TRUE)) {
        stop("Pacote dbscan é necessário para este método")
      }
      
      eps_value <- 0.3 # Valor padrão, pode ser ajustado
      dbscan_result <- dbscan::dbscan(cluster_data, eps = eps_value, minPts = min_points)
      clusters <- dbscan_result$cluster
    }
    
    # Adicionar clusters aos dados originais
    clean_data$cluster <- as.factor(clusters)
    
    # Calcular estatísticas dos clusters
    cluster_stats <- clean_data %>%
      group_by(cluster) %>%
      summarise(
        count = n(),
        avg_value = mean(!!sym(cluster_variable), na.rm = TRUE),
        min_value = min(!!sym(cluster_variable), na.rm = TRUE),
        max_value = max(!!sym(cluster_variable), na.rm = TRUE),
        avg_lat = mean(latitude, na.rm = TRUE),
        avg_lon = mean(longitude, na.rm = TRUE),
        .groups = "drop"
      )
    
    # Adicionar metadados
    attr(clean_data, "cluster_stats") <- cluster_stats
    attr(clean_data, "cluster_method") <- method
    attr(clean_data, "cluster_variable") <- cluster_variable
    attr(clean_data, "n_clusters") <- length(unique(clusters))
    attr(clean_data, "clustered_at") <- Sys.time()
    
    cli_alert_success(glue("Clusterização concluída: {length(unique(clusters))} clusters identificados"))
    
    return(clean_data)
    
  }, error = function(e) {
    stop("Erro na clusterização: ", e$message)
  })
}