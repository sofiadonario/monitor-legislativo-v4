#' @title Funções de Analytics do Monitor Legislativo
#' @description Funções para análise avançada e métricas de dados legislativos brasileiros
#' @author Monitor Legislativo Research Team
#' @importFrom dplyr tibble bind_rows filter arrange select mutate group_by summarise count
#' @importFrom purrr map_dfr map_chr map_dbl safely
#' @importFrom ggplot2 ggplot aes geom_line geom_bar geom_point scale_x_date theme_minimal labs
#' @importFrom lubridate ymd year month floor_date
#' @importFrom cli cli_alert_info cli_alert_success cli_progress_bar
#' @importFrom glue glue

#' Obter métricas gerais da plataforma
#'
#' @description
#' Recupera métricas gerais e estatísticas da plataforma Monitor Legislativo,
#' incluindo contadores de documentos, categorias, e atividade temporal.
#'
#' @param time_period String. Período para métricas temporais: "day", "week", "month", "year", "all".
#' @param include_trends Logical. Incluir tendências e variações temporais.
#' @param breakdown_by String. Quebra adicional: "category", "state", "document_type".
#' @param top_n Integer. Número de itens top a incluir em rankings.
#' 
#' @return List com métricas organizadas por categoria.
#' 
#' @examples
#' \dontrun{
#' # Métricas gerais
#' metrics <- ml_get_metrics()
#' print(metrics$summary)
#' 
#' # Métricas mensais com tendências
#' monthly_metrics <- ml_get_metrics(
#'   time_period = "month",
#'   include_trends = TRUE,
#'   breakdown_by = "category"
#' )
#' 
#' # Top 10 estados por atividade
#' state_metrics <- ml_get_metrics(
#'   breakdown_by = "state",
#'   top_n = 10
#' )
#' }
#' 
#' @export
ml_get_metrics <- function(time_period = "all",
                          include_trends = TRUE,
                          breakdown_by = NULL,
                          top_n = 10) {
  
  # Validar parâmetros
  if (!time_period %in% c("day", "week", "month", "year", "all")) {
    stop("time_period deve ser um de: 'day', 'week', 'month', 'year', 'all'")
  }
  
  if (!is.null(breakdown_by) && !breakdown_by %in% c("category", "state", "document_type")) {
    stop("breakdown_by deve ser um de: 'category', 'state', 'document_type'")
  }
  
  top_n <- max(1, min(as.integer(top_n), 100))
  
  cli_alert_info("Recuperando métricas da plataforma...")
  
  # Preparar parâmetros da requisição
  params <- list(
    time_period = time_period,
    include_trends = include_trends,
    top_n = top_n
  )
  
  if (!is.null(breakdown_by)) {
    params$breakdown_by <- breakdown_by
  }
  
  # Construir URL
  query_string <- paste(
    names(params),
    vapply(params, function(x) URLencode(as.character(x)), character(1)),
    sep = "=",
    collapse = "&"
  )
  
  endpoint <- glue("/analytics/metrics?{query_string}")
  
  tryCatch({
    result <- .ml_api_call("GET", endpoint)
    
    if (is.null(result) || !result$success) {
      stop("Erro ao obter métricas: ", result$message %||% "Erro desconhecido")
    }
    
    metrics_data <- result$data %||% list()
    
    # Organizar métricas
    metrics <- list(
      summary = list(
        total_documents = as.integer(metrics_data$summary$total_documents %||% 0),
        total_categories = as.integer(metrics_data$summary$total_categories %||% 0),
        total_states = as.integer(metrics_data$summary$total_states %||% 0),
        total_municipalities = as.integer(metrics_data$summary$total_municipalities %||% 0),
        date_range_start = as.character(metrics_data$summary$date_range_start %||% ""),
        date_range_end = as.character(metrics_data$summary$date_range_end %||% ""),
        last_update = as.character(metrics_data$summary$last_update %||% "")
      ),
      temporal = list(),
      breakdown = list(),
      trends = list()
    )
    
    # Adicionar dados temporais se disponíveis
    if (!is.null(metrics_data$temporal)) {
      metrics$temporal <- map_dfr(metrics_data$temporal, function(item) {
        tibble(
          period = as.character(item$period %||% ""),
          document_count = as.integer(item$document_count %||% 0),
          unique_categories = as.integer(item$unique_categories %||% 0),
          unique_states = as.integer(item$unique_states %||% 0)
        )
      })
    }
    
    # Adicionar breakdown se disponível
    if (!is.null(metrics_data$breakdown)) {
      metrics$breakdown <- map_dfr(metrics_data$breakdown, function(item) {
        tibble(
          category = as.character(item$name %||% ""),
          document_count = as.integer(item$count %||% 0),
          percentage = as.numeric(item$percentage %||% 0),
          rank = as.integer(item$rank %||% 0)
        )
      })
    }
    
    # Adicionar tendências se solicitadas
    if (include_trends && !is.null(metrics_data$trends)) {
      metrics$trends <- list(
        growth_rate = as.numeric(metrics_data$trends$growth_rate %||% 0),
        trend_direction = as.character(metrics_data$trends$direction %||% "stable"),
        seasonal_patterns = metrics_data$trends$seasonal_patterns %||% list(),
        peak_periods = metrics_data$trends$peak_periods %||% list()
      )
    }
    
    # Adicionar metadados
    attr(metrics, "generated_at") <- Sys.time()
    attr(metrics, "time_period") <- time_period
    attr(metrics, "breakdown_by") <- breakdown_by
    
    cli_alert_success("Métricas recuperadas com sucesso")
    
    return(metrics)
    
  }, error = function(e) {
    stop("Erro ao obter métricas: ", e$message)
  })
}

#' Analisar tendências temporais
#'
#' @description
#' Realiza análise de tendências temporais na legislação brasileira,
#' identificando padrões sazonais, picos de atividade e evolução histórica.
#'
#' @param query String. Termo de busca para filtrar análise (opcional).
#' @param time_granularity String. Granularidade temporal: "day", "week", "month", "quarter", "year".
#' @param date_range Vector. Intervalo de datas para análise (c(início, fim)).
#' @param category String. Categoria específica para análise.
#' @param state String. Estado específico para análise.
#' @param trend_analysis Vector. Tipos de análise: "volume", "diversity", "complexity", "seasonal".
#' @param include_forecast Logical. Incluir previsões futuras.
#' @param visualization Logical. Gerar visualizações automáticas.
#' 
#' @return List com análises de tendência e visualizações opcionais.
#' 
#' @examples
#' \dontrun{
#' # Análise de tendências gerais
#' trends <- ml_analyze_trends(
#'   time_granularity = "month",
#'   trend_analysis = c("volume", "diversity"),
#'   visualization = TRUE
#' )
#' 
#' # Tendências específicas por tema
#' covid_trends <- ml_analyze_trends(
#'   query = "covid-19",
#'   time_granularity = "week",
#'   date_range = c("2020-01-01", "2023-12-31"),
#'   include_forecast = TRUE
#' )
#' 
#' # Análise estadual
#' sp_trends <- ml_analyze_trends(
#'   state = "SP",
#'   time_granularity = "quarter",
#'   trend_analysis = c("volume", "complexity", "seasonal")
#' )
#' }
#' 
#' @export
ml_analyze_trends <- function(query = NULL,
                             time_granularity = "month",
                             date_range = NULL,
                             category = NULL,
                             state = NULL,
                             trend_analysis = c("volume", "diversity"),
                             include_forecast = FALSE,
                             visualization = FALSE) {
  
  # Validar parâmetros
  if (!time_granularity %in% c("day", "week", "month", "quarter", "year")) {
    stop("time_granularity deve ser um de: 'day', 'week', 'month', 'quarter', 'year'")
  }
  
  valid_analyses <- c("volume", "diversity", "complexity", "seasonal")
  trend_analysis <- intersect(trend_analysis, valid_analyses)
  
  if (length(trend_analysis) == 0) {
    trend_analysis <- c("volume", "diversity")
  }
  
  cli_alert_info("Iniciando análise de tendências...")
  
  # Preparar body da requisição
  request_body <- list(
    query = query,
    time_granularity = time_granularity,
    date_range = date_range,
    category = category,
    state = state,
    trend_analysis = trend_analysis,
    include_forecast = include_forecast,
    visualization = visualization
  )
  
  tryCatch({
    result <- .ml_api_call("POST", "/analytics/trends", body = request_body)
    
    if (is.null(result) || !result$success) {
      stop("Erro na análise de tendências: ", result$message %||% "Erro desconhecido")
    }
    
    trends_data <- result$data %||% list()
    
    # Organizar resultados da análise
    trends_analysis <- list(
      time_series = list(),
      statistics = list(),
      patterns = list(),
      forecast = list(),
      visualizations = list()
    )
    
    # Processar séries temporais
    if (!is.null(trends_data$time_series)) {
      trends_analysis$time_series <- map_dfr(trends_data$time_series, function(item) {
        tibble(
          period = as.character(item$period %||% ""),
          date = as.Date(item$date %||% Sys.Date()),
          volume = as.integer(item$volume %||% 0),
          diversity_index = as.numeric(item$diversity_index %||% 0),
          complexity_score = as.numeric(item$complexity_score %||% 0),
          seasonal_component = as.numeric(item$seasonal_component %||% 0),
          trend_component = as.numeric(item$trend_component %||% 0)
        )
      })
    }
    
    # Processar estatísticas
    if (!is.null(trends_data$statistics)) {
      trends_analysis$statistics <- list(
        total_periods = as.integer(trends_data$statistics$total_periods %||% 0),
        avg_volume = as.numeric(trends_data$statistics$avg_volume %||% 0),
        volume_std = as.numeric(trends_data$statistics$volume_std %||% 0),
        trend_slope = as.numeric(trends_data$statistics$trend_slope %||% 0),
        seasonality_strength = as.numeric(trends_data$statistics$seasonality_strength %||% 0),
        peak_period = as.character(trends_data$statistics$peak_period %||% ""),
        trough_period = as.character(trends_data$statistics$trough_period %||% "")
      )
    }
    
    # Processar padrões identificados
    if (!is.null(trends_data$patterns)) {
      trends_analysis$patterns <- list(
        seasonal_peaks = trends_data$patterns$seasonal_peaks %||% list(),
        cyclical_patterns = trends_data$patterns$cyclical_patterns %||% list(),
        anomalies = trends_data$patterns$anomalies %||% list(),
        correlations = trends_data$patterns$correlations %||% list()
      )
    }
    
    # Processar previsões se disponíveis
    if (include_forecast && !is.null(trends_data$forecast)) {
      trends_analysis$forecast <- map_dfr(trends_data$forecast, function(item) {
        tibble(
          period = as.character(item$period %||% ""),
          date = as.Date(item$date %||% Sys.Date()),
          predicted_volume = as.numeric(item$predicted_volume %||% 0),
          confidence_lower = as.numeric(item$confidence_lower %||% 0),
          confidence_upper = as.numeric(item$confidence_upper %||% 0),
          forecast_method = as.character(item$method %||% "")
        )
      })
    }
    
    # Gerar visualizações se solicitado
    if (visualization && nrow(trends_analysis$time_series) > 0) {
      trends_analysis$visualizations <- .create_trend_visualizations(trends_analysis, trend_analysis)
    }
    
    # Adicionar metadados
    attr(trends_analysis, "analysis_params") <- request_body
    attr(trends_analysis, "generated_at") <- Sys.time()
    
    cli_alert_success("Análise de tendências concluída")
    
    return(trends_analysis)
    
  }, error = function(e) {
    stop("Erro na análise de tendências: ", e$message)
  })
}

# Função interna para criar visualizações de tendências
.create_trend_visualizations <- function(trends_data, trend_analysis) {
  
  if (!requireNamespace("ggplot2", quietly = TRUE)) {
    warning("ggplot2 necessário para visualizações")
    return(list())
  }
  
  visualizations <- list()
  time_series <- trends_data$time_series
  
  tryCatch({
    # Gráfico de volume ao longo do tempo
    if ("volume" %in% trend_analysis && "volume" %in% names(time_series)) {
      volume_plot <- ggplot(time_series, aes(x = date, y = volume)) +
        geom_line(color = "steelblue", size = 1) +
        geom_point(color = "steelblue", size = 2) +
        theme_minimal() +
        labs(
          title = "Volume de Documentos Legislativos ao Longo do Tempo",
          x = "Período",
          y = "Número de Documentos",
          caption = "Fonte: Monitor Legislativo"
        )
      
      visualizations$volume_trend <- volume_plot
    }
    
    # Gráfico de diversidade
    if ("diversity" %in% trend_analysis && "diversity_index" %in% names(time_series)) {
      diversity_plot <- ggplot(time_series, aes(x = date, y = diversity_index)) +
        geom_line(color = "forestgreen", size = 1) +
        geom_smooth(method = "loess", se = TRUE, alpha = 0.3) +
        theme_minimal() +
        labs(
          title = "Índice de Diversidade Legislativa",
          x = "Período",
          y = "Índice de Diversidade",
          caption = "Fonte: Monitor Legislativo"
        )
      
      visualizations$diversity_trend <- diversity_plot
    }
    
    # Gráfico de sazonalidade
    if ("seasonal" %in% trend_analysis && "seasonal_component" %in% names(time_series)) {
      seasonal_plot <- ggplot(time_series, aes(x = date, y = seasonal_component)) +
        geom_line(color = "coral", size = 1) +
        geom_hline(yintercept = 0, linetype = "dashed", alpha = 0.5) +
        theme_minimal() +
        labs(
          title = "Componente Sazonal da Atividade Legislativa",
          x = "Período",
          y = "Componente Sazonal",
          caption = "Fonte: Monitor Legislativo"
        )
      
      visualizations$seasonal_pattern <- seasonal_plot
    }
    
    # Gráfico combinado se múltiplas análises
    if (length(trend_analysis) > 1) {
      # Normalizar dados para visualização combinada
      normalized_data <- time_series %>%
        mutate(
          volume_norm = if ("volume" %in% names(.)) scale(volume)[,1] else NA,
          diversity_norm = if ("diversity_index" %in% names(.)) scale(diversity_index)[,1] else NA,
          complexity_norm = if ("complexity_score" %in% names(.)) scale(complexity_score)[,1] else NA
        ) %>%
        select(date, ends_with("_norm")) %>%
        pivot_longer(cols = ends_with("_norm"), names_to = "metric", values_to = "value") %>%
        filter(!is.na(value))
      
      if (nrow(normalized_data) > 0) {
        combined_plot <- ggplot(normalized_data, aes(x = date, y = value, color = metric)) +
          geom_line(size = 1) +
          theme_minimal() +
          labs(
            title = "Tendências Legislativas Normalizadas",
            x = "Período",
            y = "Valor Normalizado",
            color = "Métrica",
            caption = "Fonte: Monitor Legislativo"
          ) +
          scale_color_discrete(
            labels = c("Complexidade", "Diversidade", "Volume")
          )
        
        visualizations$combined_trends <- combined_plot
      }
    }
    
  }, error = function(e) {
    warning("Erro ao criar visualizações: ", e$message)
  })
  
  return(visualizations)
}

#' Obter dados para dashboard
#'
#' @description
#' Recupera dados agregados e pré-processados para construção de dashboards
#' interativos, incluindo métricas-chave, gráficos e tabelas resumo.
#'
#' @param dashboard_type String. Tipo de dashboard: "overview", "geographic", "temporal", "thematic".
#' @param time_period String. Período para dados: "7days", "30days", "90days", "1year", "all".
#' @param refresh_cache Logical. Forçar atualização do cache.
#' @param include_charts Logical. Incluir dados pré-processados para gráficos.
#' @param format String. Formato dos dados: "json", "tibble", "list".
#' 
#' @return List ou tibble com dados estruturados para dashboard.
#' 
#' @examples
#' \dontrun{
#' # Dashboard overview
#' overview_data <- ml_dashboard_data(
#'   dashboard_type = "overview",
#'   time_period = "30days",
#'   include_charts = TRUE
#' )
#' 
#' # Dashboard geográfico
#' geo_data <- ml_dashboard_data(
#'   dashboard_type = "geographic",
#'   format = "tibble"
#' )
#' 
#' # Dashboard temporal com cache atualizado
#' temporal_data <- ml_dashboard_data(
#'   dashboard_type = "temporal",
#'   time_period = "1year",
#'   refresh_cache = TRUE
#' )
#' }
#' 
#' @export
ml_dashboard_data <- function(dashboard_type = "overview",
                             time_period = "30days",
                             refresh_cache = FALSE,
                             include_charts = TRUE,
                             format = "list") {
  
  # Validar parâmetros
  if (!dashboard_type %in% c("overview", "geographic", "temporal", "thematic")) {
    stop("dashboard_type deve ser um de: 'overview', 'geographic', 'temporal', 'thematic'")
  }
  
  if (!time_period %in% c("7days", "30days", "90days", "1year", "all")) {
    stop("time_period deve ser um de: '7days', '30days', '90days', '1year', 'all'")
  }
  
  if (!format %in% c("json", "tibble", "list")) {
    stop("format deve ser um de: 'json', 'tibble', 'list'")
  }
  
  cli_alert_info(glue("Carregando dados do dashboard {dashboard_type}..."))
  
  # Preparar parâmetros
  params <- list(
    dashboard_type = dashboard_type,
    time_period = time_period,
    refresh_cache = refresh_cache,
    include_charts = include_charts,
    format = format
  )
  
  # Construir URL
  query_string <- paste(
    names(params),
    vapply(params, function(x) URLencode(as.character(x)), character(1)),
    sep = "=",
    collapse = "&"
  )
  
  endpoint <- glue("/analytics/dashboard?{query_string}")
  
  tryCatch({
    result <- .ml_api_call("GET", endpoint)
    
    if (is.null(result) || !result$success) {
      stop("Erro ao obter dados do dashboard: ", result$message %||% "Erro desconhecido")
    }
    
    dashboard_data <- result$data %||% list()
    
    # Processar dados baseado no tipo de dashboard
    processed_data <- .process_dashboard_data(dashboard_data, dashboard_type, format, include_charts)
    
    # Adicionar metadados
    attr(processed_data, "dashboard_type") <- dashboard_type
    attr(processed_data, "time_period") <- time_period
    attr(processed_data, "generated_at") <- Sys.time()
    attr(processed_data, "cache_refreshed") <- refresh_cache
    
    cli_alert_success("Dados do dashboard carregados com sucesso")
    
    return(processed_data)
    
  }, error = function(e) {
    stop("Erro ao obter dados do dashboard: ", e$message)
  })
}

# Função interna para processar dados do dashboard
.process_dashboard_data <- function(dashboard_data, dashboard_type, format, include_charts) {
  
  processed <- list()
  
  if (dashboard_type == "overview") {
    # Dashboard geral
    processed$summary <- list(
      total_documents = as.integer(dashboard_data$summary$total_documents %||% 0),
      new_documents_period = as.integer(dashboard_data$summary$new_documents_period %||% 0),
      active_categories = as.integer(dashboard_data$summary$active_categories %||% 0),
      coverage_states = as.integer(dashboard_data$summary$coverage_states %||% 0)
    )
    
    processed$recent_activity <- map_dfr(dashboard_data$recent_activity %||% list(), function(item) {
      tibble(
        date = as.character(item$date %||% ""),
        document_count = as.integer(item$count %||% 0),
        category = as.character(item$top_category %||% "")
      )
    })
    
    processed$top_categories <- map_dfr(dashboard_data$top_categories %||% list(), function(item) {
      tibble(
        category = as.character(item$name %||% ""),
        count = as.integer(item$count %||% 0),
        percentage = as.numeric(item$percentage %||% 0)
      )
    })
    
  } else if (dashboard_type == "geographic") {
    # Dashboard geográfico
    processed$state_distribution <- map_dfr(dashboard_data$state_distribution %||% list(), function(item) {
      tibble(
        state = as.character(item$state %||% ""),
        state_code = as.character(item$code %||% ""),
        document_count = as.integer(item$count %||% 0),
        density_per_1000 = as.numeric(item$density %||% 0)
      )
    })
    
    processed$regional_summary <- map_dfr(dashboard_data$regional_summary %||% list(), function(item) {
      tibble(
        region = as.character(item$region %||% ""),
        total_documents = as.integer(item$total %||% 0),
        avg_per_state = as.numeric(item$avg_per_state %||% 0)
      )
    })
    
  } else if (dashboard_type == "temporal") {
    # Dashboard temporal
    processed$time_series <- map_dfr(dashboard_data$time_series %||% list(), function(item) {
      tibble(
        date = as.Date(item$date %||% Sys.Date()),
        count = as.integer(item$count %||% 0),
        cumulative = as.integer(item$cumulative %||% 0)
      )
    })
    
    processed$seasonal_patterns <- map_dfr(dashboard_data$seasonal_patterns %||% list(), function(item) {
      tibble(
        month = as.integer(item$month %||% 1),
        avg_documents = as.numeric(item$avg_documents %||% 0),
        pattern_strength = as.numeric(item$strength %||% 0)
      )
    })
    
  } else if (dashboard_type == "thematic") {
    # Dashboard temático
    processed$theme_analysis <- map_dfr(dashboard_data$theme_analysis %||% list(), function(item) {
      tibble(
        theme = as.character(item$theme %||% ""),
        document_count = as.integer(item$count %||% 0),
        growth_rate = as.numeric(item$growth %||% 0),
        relevance_score = as.numeric(item$relevance %||% 0)
      )
    })
    
    processed$keyword_trends <- map_dfr(dashboard_data$keyword_trends %||% list(), function(item) {
      tibble(
        keyword = as.character(item$keyword %||% ""),
        frequency = as.integer(item$frequency %||% 0),
        trend = as.character(item$trend %||% "stable")
      )
    })
  }
  
  # Adicionar dados de gráficos se solicitado
  if (include_charts && !is.null(dashboard_data$charts)) {
    processed$charts <- dashboard_data$charts
  }
  
  # Converter formato se necessário
  if (format == "tibble" && dashboard_type == "overview") {
    # Combinar dados principais em um tibble
    return(processed$recent_activity)
  } else if (format == "json") {
    return(jsonlite::toJSON(processed, auto_unbox = TRUE, pretty = TRUE))
  }
  
  return(processed)
}

#' Análise comparativa entre períodos
#'
#' @description
#' Realiza análise comparativa da atividade legislativa entre diferentes
#' períodos temporais, identificando mudanças e tendências significativas.
#'
#' @param period1 Vector. Período 1 para comparação (c(início, fim)).
#' @param period2 Vector. Período 2 para comparação (c(início, fim)).
#' @param comparison_metrics Vector. Métricas a comparar: "volume", "diversity", "geographic", "thematic".
#' @param significance_test Logical. Realizar testes de significância estatística.
#' @param visualization Logical. Gerar visualizações comparativas.
#' 
#' @return List com análises comparativas e testes estatísticos.
#' 
#' @examples
#' \dontrun{
#' # Comparar período pré e pós COVID-19
#' covid_comparison <- ml_comparative_analysis(
#'   period1 = c("2018-01-01", "2019-12-31"),
#'   period2 = c("2020-01-01", "2021-12-31"),
#'   comparison_metrics = c("volume", "thematic"),
#'   significance_test = TRUE
#' )
#' 
#' # Comparar anos eleitorais vs não-eleitorais
#' electoral_comparison <- ml_comparative_analysis(
#'   period1 = c("2017-01-01", "2017-12-31"),
#'   period2 = c("2018-01-01", "2018-12-31"),
#'   comparison_metrics = c("volume", "geographic", "diversity"),
#'   visualization = TRUE
#' )
#' }
#' 
#' @export
ml_comparative_analysis <- function(period1,
                                   period2,
                                   comparison_metrics = c("volume", "diversity"),
                                   significance_test = FALSE,
                                   visualization = FALSE) {
  
  # Validar períodos
  if (length(period1) != 2 || length(period2) != 2) {
    stop("Períodos devem ter formato c(início, fim)")
  }
  
  valid_metrics <- c("volume", "diversity", "geographic", "thematic")
  comparison_metrics <- intersect(comparison_metrics, valid_metrics)
  
  if (length(comparison_metrics) == 0) {
    comparison_metrics <- c("volume", "diversity")
  }
  
  cli_alert_info("Iniciando análise comparativa entre períodos...")
  
  # Preparar requisição
  request_body <- list(
    period1 = list(start = period1[1], end = period1[2]),
    period2 = list(start = period2[1], end = period2[2]),
    comparison_metrics = comparison_metrics,
    significance_test = significance_test,
    visualization = visualization
  )
  
  tryCatch({
    result <- .ml_api_call("POST", "/analytics/comparative", body = request_body)
    
    if (is.null(result) || !result$success) {
      stop("Erro na análise comparativa: ", result$message %||% "Erro desconhecido")
    }
    
    comparison_data <- result$data %||% list()
    
    # Organizar resultados
    analysis <- list(
      summary = list(),
      metrics = list(),
      statistical_tests = list(),
      visualizations = list()
    )
    
    # Resumo da comparação
    if (!is.null(comparison_data$summary)) {
      analysis$summary <- list(
        period1_total = as.integer(comparison_data$summary$period1_total %||% 0),
        period2_total = as.integer(comparison_data$summary$period2_total %||% 0),
        absolute_change = as.integer(comparison_data$summary$absolute_change %||% 0),
        percentage_change = as.numeric(comparison_data$summary$percentage_change %||% 0),
        change_direction = as.character(comparison_data$summary$direction %||% "stable")
      )
    }
    
    # Métricas detalhadas
    if (!is.null(comparison_data$metrics)) {
      for (metric in names(comparison_data$metrics)) {
        metric_data <- comparison_data$metrics[[metric]]
        analysis$metrics[[metric]] <- list(
          period1_value = as.numeric(metric_data$period1 %||% 0),
          period2_value = as.numeric(metric_data$period2 %||% 0),
          change = as.numeric(metric_data$change %||% 0),
          change_percentage = as.numeric(metric_data$change_pct %||% 0)
        )
      }
    }
    
    # Testes estatísticos se solicitados
    if (significance_test && !is.null(comparison_data$statistical_tests)) {
      analysis$statistical_tests <- comparison_data$statistical_tests
    }
    
    # Visualizações se solicitadas
    if (visualization && !is.null(comparison_data$visualizations)) {
      analysis$visualizations <- comparison_data$visualizations
    }
    
    # Adicionar metadados
    attr(analysis, "comparison_periods") <- list(period1 = period1, period2 = period2)
    attr(analysis, "metrics_compared") <- comparison_metrics
    attr(analysis, "analysis_date") <- Sys.time()
    
    cli_alert_success("Análise comparativa concluída")
    
    return(analysis)
    
  }, error = function(e) {
    stop("Erro na análise comparativa: ", e$message)
  })
}