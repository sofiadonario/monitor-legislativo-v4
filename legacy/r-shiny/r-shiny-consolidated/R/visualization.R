# Visualization Functions for Monitor Legislativo v4
# Modern charts and visualizations using echarts4r

library(echarts4r)
library(dplyr)
library(lubridate)
library(RColorBrewer)
library(scales)

#' Create interactive bar chart for document types
#' @param data Legislative data
#' @param top_n Number of top categories to show
#' @return echarts4r object
create_type_distribution_chart <- function(data, top_n = 10) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Prepare data
  type_data <- data %>%
    filter(!is.na(tipo)) %>%
    count(tipo, sort = TRUE) %>%
    slice_head(n = top_n) %>%
    mutate(
      tipo = stringr::str_to_title(tipo),
      percentage = round(n / sum(n) * 100, 1)
    )
  
  # Create chart
  chart <- type_data %>%
    e_charts(tipo) %>%
    e_bar(
      n, 
      name = "Documentos",
      itemStyle = list(
        borderRadius = c(4, 4, 0, 0),
        borderWidth = 1,
        borderColor = "#fff"
      )
    ) %>%
    e_tooltip(
      trigger = "axis",
      formatter = htmlwidgets::JS("
        function(params) {
          var data = params[0];
          return '<strong>' + data.name + '</strong><br>' +
                 'Documentos: ' + data.value.toLocaleString() + '<br>' +
                 'Porcentagem: ' + data.data.percentage + '%';
        }
      ")
    ) %>%
    e_title(
      text = "Distribuição por Tipo de Documento",
      left = "center",
      textStyle = list(
        fontSize = 16,
        fontWeight = "bold"
      )
    ) %>%
    e_grid(
      left = "3%",
      right = "4%",
      bottom = "3%",
      containLabel = TRUE
    ) %>%
    e_x_axis(
      axisLabel = list(
        rotate = 45,
        interval = 0
      )
    ) %>%
    e_y_axis(
      axisLabel = list(
        formatter = htmlwidgets::JS("function(value) { return value.toLocaleString(); }")
      )
    ) %>%
    e_color(c("#5470c6", "#91cc75", "#fac858", "#ee6666", "#73c0de", "#3ba272", "#fc8452", "#9a60b4", "#ea7ccc")) %>%
    e_theme("macarons") %>%
    e_animation(duration = 1000)
  
  return(chart)
}

#' Create temporal distribution line chart
#' @param data Legislative data
#' @param period Aggregation period ("year", "month", "quarter")
#' @return echarts4r object
create_temporal_chart <- function(data, period = "year") {
  
  if (is.null(data) || nrow(data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Prepare temporal data
  temporal_data <- data %>%
    filter(!is.na(data)) %>%
    mutate(date_parsed = as.Date(data))
  
  if (nrow(temporal_data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados temporais para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Aggregate by period
  if (period == "year") {
    temporal_summary <- temporal_data %>%
      mutate(period = year(date_parsed)) %>%
      count(period, sort = FALSE) %>%
      rename(year = period, documents = n)
    
    x_axis_title <- "Ano"
    title_text <- "Distribuição Temporal - Por Ano"
    
  } else if (period == "month") {
    temporal_summary <- temporal_data %>%
      mutate(period = floor_date(date_parsed, "month")) %>%
      count(period, sort = FALSE) %>%
      mutate(period = format(period, "%Y-%m")) %>%
      rename(month = period, documents = n)
    
    x_axis_title <- "Mês"
    title_text <- "Distribuição Temporal - Por Mês"
    
  } else if (period == "quarter") {
    temporal_summary <- temporal_data %>%
      mutate(
        year = year(date_parsed),
        quarter = quarter(date_parsed),
        period = paste0(year, "-Q", quarter)
      ) %>%
      count(period, sort = FALSE) %>%
      rename(quarter = period, documents = n)
    
    x_axis_title <- "Trimestre"
    title_text <- "Distribuição Temporal - Por Trimestre"
    
  } else {
    # Default to year
    temporal_summary <- temporal_data %>%
      mutate(period = year(date_parsed)) %>%
      count(period, sort = FALSE) %>%
      rename(year = period, documents = n)
    
    x_axis_title <- "Ano"
    title_text <- "Distribuição Temporal - Por Ano"
  }
  
  # Create chart
  chart <- temporal_summary %>%
    e_charts(names(temporal_summary)[1]) %>%
    e_line(
      documents,
      smooth = TRUE,
      symbol = "circle",
      symbolSize = 6,
      lineStyle = list(width = 3),
      areaStyle = list(opacity = 0.3)
    ) %>%
    e_tooltip(
      trigger = "axis",
      formatter = htmlwidgets::JS("
        function(params) {
          var data = params[0];
          return '<strong>' + data.name + '</strong><br>' +
                 'Documentos: ' + data.value.toLocaleString();
        }
      ")
    ) %>%
    e_title(
      text = title_text,
      left = "center",
      textStyle = list(
        fontSize = 16,
        fontWeight = "bold"
      )
    ) %>%
    e_grid(
      left = "3%",
      right = "4%",
      bottom = "3%",
      containLabel = TRUE
    ) %>%
    e_x_axis(
      name = x_axis_title,
      nameLocation = "middle",
      nameGap = 30
    ) %>%
    e_y_axis(
      name = "Número de Documentos",
      nameLocation = "middle",
      nameGap = 40,
      axisLabel = list(
        formatter = htmlwidgets::JS("function(value) { return value.toLocaleString(); }")
      )
    ) %>%
    e_color("#5470c6") %>%
    e_theme("macarons") %>%
    e_animation(duration = 1000) %>%
    e_datazoom(
      type = "slider",
      start = 0,
      end = 100
    )
  
  return(chart)
}

#' Create geographic distribution pie chart
#' @param data Legislative data
#' @param top_n Number of top states to show
#' @return echarts4r object
create_geographic_pie_chart <- function(data, top_n = 8) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Prepare geographic data
  geo_data <- data %>%
    filter(!is.na(estado)) %>%
    count(estado, sort = TRUE)
  
  if (nrow(geo_data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados geográficos para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Get top states and group others
  if (nrow(geo_data) > top_n) {
    top_states <- geo_data %>%
      slice_head(n = top_n - 1)
    
    others_count <- geo_data %>%
      slice_tail(n = -(top_n - 1)) %>%
      summarise(n = sum(n)) %>%
      pull(n)
    
    geo_summary <- bind_rows(
      top_states,
      data.frame(estado = "Outros", n = others_count)
    )
  } else {
    geo_summary <- geo_data
  }
  
  # Calculate percentages
  geo_summary <- geo_summary %>%
    mutate(
      percentage = round(n / sum(n) * 100, 1),
      label = paste0(estado, " (", percentage, "%)")
    )
  
  # Create pie chart
  chart <- geo_summary %>%
    e_charts() %>%
    e_pie(
      n,
      name = "Documentos por Estado",
      radius = c("40%", "70%"),
      center = c("50%", "50%"),
      itemStyle = list(
        borderRadius = 8,
        borderColor = "#fff",
        borderWidth = 2
      ),
      label = list(
        show = TRUE,
        formatter = "{b}: {c} ({d}%)"
      ),
      emphasis = list(
        itemStyle = list(
          shadowBlur = 10,
          shadowOffsetX = 0,
          shadowColor = "rgba(0, 0, 0, 0.5)"
        )
      )
    ) %>%
    e_tooltip(
      trigger = "item",
      formatter = htmlwidgets::JS("
        function(params) {
          return '<strong>' + params.name + '</strong><br>' +
                 'Documentos: ' + params.value.toLocaleString() + '<br>' +
                 'Porcentagem: ' + params.percent + '%';
        }
      ")
    ) %>%
    e_title(
      text = "Distribuição Geográfica",
      left = "center",
      textStyle = list(
        fontSize = 16,
        fontWeight = "bold"
      )
    ) %>%
    e_legend(
      orient = "vertical",
      left = "left",
      top = "middle"
    ) %>%
    e_color(c("#5470c6", "#91cc75", "#fac858", "#ee6666", "#73c0de", "#3ba272", "#fc8452", "#9a60b4", "#ea7ccc")) %>%
    e_theme("macarons") %>%
    e_animation(duration = 1000)
  
  return(chart)
}

#' Create multi-series chart comparing different dimensions
#' @param data Legislative data
#' @param x_var X-axis variable (e.g., "year", "state", "type")
#' @param group_var Grouping variable for series
#' @param chart_type Chart type ("bar", "line")
#' @return echarts4r object
create_comparison_chart <- function(data, x_var = "year", group_var = "tipo", chart_type = "bar") {
  
  if (is.null(data) || nrow(data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Prepare data based on variables
  if (x_var == "year") {
    comparison_data <- data %>%
      filter(!is.na(data), !is.na(!!sym(group_var))) %>%
      mutate(x_value = year(as.Date(data))) %>%
      count(x_value, !!sym(group_var)) %>%
      pivot_wider(names_from = !!sym(group_var), values_from = n, values_fill = 0)
    
    x_title <- "Ano"
    chart_title <- paste("Comparação por", stringr::str_to_title(group_var), "ao longo do tempo")
    
  } else if (x_var == "state") {
    comparison_data <- data %>%
      filter(!is.na(estado), !is.na(!!sym(group_var))) %>%
      count(estado, !!sym(group_var)) %>%
      pivot_wider(names_from = !!sym(group_var), values_from = n, values_fill = 0) %>%
      rename(x_value = estado)
    
    x_title <- "Estado"
    chart_title <- paste("Comparação por", stringr::str_to_title(group_var), "por Estado")
    
  } else {
    # Default to type comparison
    comparison_data <- data %>%
      filter(!is.na(tipo)) %>%
      mutate(x_value = year(as.Date(data))) %>%
      count(x_value, tipo) %>%
      pivot_wider(names_from = tipo, values_from = n, values_fill = 0)
    
    x_title <- "Ano"
    chart_title <- "Comparação por Tipo ao longo do tempo"
  }
  
  if (nrow(comparison_data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados suficientes para comparação") %>%
        e_theme("macarons")
    )
  }
  
  # Create base chart
  chart <- comparison_data %>%
    e_charts(x_value)
  
  # Add series based on chart type
  series_columns <- names(comparison_data)[-1]  # Exclude x_value column
  
  for (i in seq_along(series_columns)) {
    col_name <- series_columns[i]
    
    if (chart_type == "line") {
      chart <- chart %>%
        e_line(
          !!sym(col_name),
          name = stringr::str_to_title(col_name),
          smooth = TRUE,
          symbol = "circle",
          symbolSize = 4
        )
    } else {
      chart <- chart %>%
        e_bar(
          !!sym(col_name),
          name = stringr::str_to_title(col_name),
          stack = "total"
        )
    }
  }
  
  # Configure chart
  chart <- chart %>%
    e_tooltip(
      trigger = "axis",
      axisPointer = list(type = "shadow")
    ) %>%
    e_title(
      text = chart_title,
      left = "center",
      textStyle = list(
        fontSize = 16,
        fontWeight = "bold"
      )
    ) %>%
    e_legend(
      top = "top",
      left = "center",
      orient = "horizontal"
    ) %>%
    e_grid(
      left = "3%",
      right = "4%",
      bottom = "3%",
      containLabel = TRUE
    ) %>%
    e_x_axis(
      name = x_title,
      nameLocation = "middle",
      nameGap = 30
    ) %>%
    e_y_axis(
      name = "Número de Documentos",
      nameLocation = "middle",
      nameGap = 40,
      axisLabel = list(
        formatter = htmlwidgets::JS("function(value) { return value.toLocaleString(); }")
      )
    ) %>%
    e_color(c("#5470c6", "#91cc75", "#fac858", "#ee6666", "#73c0de", "#3ba272", "#fc8452", "#9a60b4", "#ea7ccc")) %>%
    e_theme("macarons") %>%
    e_animation(duration = 1000)
  
  # Add data zoom for large datasets
  if (nrow(comparison_data) > 20) {
    chart <- chart %>%
      e_datazoom(
        type = "slider",
        start = 0,
        end = 100
      )
  }
  
  return(chart)
}

#' Create summary statistics visualization
#' @param data Legislative data
#' @return echarts4r gauge chart
create_summary_gauge <- function(data) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Calculate quality metrics
  total_docs <- nrow(data)
  complete_docs <- sum(!is.na(data$titulo) & !is.na(data$data) & !is.na(data$tipo))
  quality_score <- round((complete_docs / total_docs) * 100, 1)
  
  # Geographic coverage
  geo_coverage <- if ("estado" %in% names(data)) {
    unique_states <- length(unique(data$estado[!is.na(data$estado)]))
    round((unique_states / 27) * 100, 1)  # 27 states including DF
  } else {
    0
  }
  
  # Temporal coverage (how recent is the data)
  if ("data" %in% names(data)) {
    latest_date <- max(as.Date(data$data), na.rm = TRUE)
    days_since_latest <- as.numeric(Sys.Date() - latest_date)
    temporal_score <- max(0, 100 - (days_since_latest / 365) * 100)  # Decay over time
    temporal_score <- round(temporal_score, 1)
  } else {
    temporal_score <- 0
  }
  
  # Create gauge chart
  gauge_data <- data.frame(
    metric = c("Qualidade dos Dados", "Cobertura Geográfica", "Atualidade dos Dados"),
    value = c(quality_score, geo_coverage, temporal_score),
    max_value = c(100, 100, 100)
  )
  
  chart <- gauge_data %>%
    e_charts() %>%
    e_gauge(
      value,
      name = "Métricas de Qualidade",
      min = 0,
      max = 100,
      splitNumber = 10,
      radius = "75%",
      center = c("50%", "55%"),
      startAngle = 225,
      endAngle = -45,
      itemStyle = list(
        color = list(
          list(0.2, "#ee6666"),
          list(0.6, "#fac858"),
          list(1, "#91cc75")
        )
      ),
      progress = list(
        show = TRUE,
        width = 18
      ),
      pointer = list(
        show = TRUE,
        length = "70%",
        width = 6
      ),
      axisLine = list(
        lineStyle = list(
          width = 18,
          color = list(
            list(0.2, "#ee6666"),
            list(0.6, "#fac858"),
            list(1, "#91cc75")
          )
        )
      ),
      axisTick = list(
        distance = -22,
        length = 8,
        lineStyle = list(
          color = "#fff",
          width = 2
        )
      ),
      splitLine = list(
        distance = -22,
        length = 14,
        lineStyle = list(
          color = "#fff",
          width = 3
        )
      ),
      axisLabel = list(
        distance = -35,
        color = "#999",
        fontSize = 12
      ),
      detail = list(
        valueAnimation = TRUE,
        formatter = "{value}%",
        color = "inherit",
        fontSize = 20,
        offsetCenter = c(0, "70%")
      )
    ) %>%
    e_title(
      text = "Métricas de Qualidade dos Dados",
      left = "center",
      textStyle = list(
        fontSize = 16,
        fontWeight = "bold"
      )
    ) %>%
    e_theme("macarons") %>%
    e_animation(duration = 2000)
  
  return(chart)
}

#' Create heatmap calendar visualization
#' @param data Legislative data
#' @param year Year to visualize
#' @return echarts4r heatmap
create_calendar_heatmap <- function(data, year = NULL) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(
      e_charts() %>%
        e_title("Sem dados para exibir") %>%
        e_theme("macarons")
    )
  }
  
  # Default to current year or most recent year in data
  if (is.null(year)) {
    if ("data" %in% names(data)) {
      year <- max(lubridate::year(as.Date(data$data)), na.rm = TRUE)
    } else {
      year <- lubridate::year(Sys.Date())
    }
  }
  
  # Prepare calendar data
  calendar_data <- data %>%
    filter(!is.na(data)) %>%
    mutate(date = as.Date(data)) %>%
    filter(lubridate::year(date) == year) %>%
    count(date) %>%
    mutate(
      date_str = format(date, "%Y-%m-%d"),
      value = n
    ) %>%
    select(date_str, value)
  
  if (nrow(calendar_data) == 0) {
    return(
      e_charts() %>%
        e_title(paste("Sem dados para o ano", year)) %>%
        e_theme("macarons")
    )
  }
  
  # Create heatmap
  chart <- calendar_data %>%
    e_charts() %>%
    e_calendar(
      range = year,
      top = 60,
      left = 30,
      right = 30,
      cellSize = c(15, 15),
      yearLabel = list(show = FALSE)
    ) %>%
    e_heatmap(
      value,
      coord_system = "calendar",
      itemStyle = list(
        borderWidth = 2,
        borderColor = "#fff"
      )
    ) %>%
    e_visual_map(
      max = max(calendar_data$value),
      inRange = list(
        color = c("#ebedf0", "#c6e48b", "#7bc96f", "#239a3b", "#196127")
      ),
      orient = "horizontal",
      left = "center",
      bottom = 10
    ) %>%
    e_tooltip(
      formatter = htmlwidgets::JS("
        function(params) {
          return '<strong>' + params.value[0] + '</strong><br>' +
                 'Documentos: ' + params.value[1];
        }
      ")
    ) %>%
    e_title(
      text = paste("Atividade Legislativa -", year),
      left = "center",
      textStyle = list(
        fontSize = 16,
        fontWeight = "bold"
      )
    ) %>%
    e_theme("macarons")
  
  return(chart)
}