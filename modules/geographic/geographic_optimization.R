# Geographic Analysis Optimization Module
# Implements PRD specifications for handling 134k+ documents efficiently

library(shiny)
library(dplyr)
library(plotly)
library(DT)
library(jsonlite)
library(memoise)
library(pool)

# Configuration for Brazilian coordinate systems
BRAZILIAN_CRS <- list(
  SIRGAS2000 = "EPSG:4674",  # Official Brazilian datum
  WGS84 = "EPSG:4326",       # International standard
  ALBERS_EQUAL_AREA = "+proj=aea +lat_1=-5 +lat_2=-42 +lat_0=-32 +lon_0=-60 +x_0=0 +y_0=0 +datum=WGS84 +units=m +no_defs"
)

# Brazilian state coordinates for mapping
BRAZIL_STATE_COORDS <- data.frame(
  state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                 "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                 "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
  lat = c(-8.77, -9.71, 1.41, -3.07, -12.96, -5.20, -15.83, -19.19, -16.64, -2.55,
          -12.64, -20.51, -18.10, -5.53, -7.06, -24.89, -8.28, -8.28, -22.84, -5.22,
          -30.01, -11.22, 1.89, -27.33, -23.55, -10.90, -10.25),
  lng = c(-70.55, -36.82, -51.77, -61.66, -38.51, -39.53, -47.86, -40.34, -49.31, -44.30,
          -55.42, -54.54, -44.38, -52.29, -35.55, -51.55, -35.07, -43.68, -43.15, -36.52,
          -51.22, -61.95, -61.22, -49.44, -46.64, -37.07, -48.25),
  stringsAsFactors = FALSE
)

# Memory management helper
monitor_memory <- function(operation_name = "operation") {
  mem_before <- as.numeric(object.size(ls(envir = .GlobalEnv))) / 1024^2
  
  function() {
    gc(verbose = FALSE, reset = TRUE)
    mem_after <- as.numeric(object.size(ls(envir = .GlobalEnv))) / 1024^2
    cat(sprintf("[%s] Memory: %.2f MB -> %.2f MB (freed: %.2f MB)\n", 
                operation_name, mem_before, mem_after, mem_before - mem_after))
  }
}

# Progressive data loading with chunking
progressive_load_geographic_data <- function(pool, chunk_size = 5000, callback = NULL) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    # Get total count
    total_query <- "SELECT COUNT(*) as total FROM documents WHERE estado IS NOT NULL AND estado != ''"
    total_docs <- dbGetQuery(conn, total_query)$total
    
    if (total_docs == 0) {
      return(data.frame())
    }
    
    chunks <- ceiling(total_docs / chunk_size)
    all_data <- list()
    
    for (i in 1:chunks) {
      offset <- (i - 1) * chunk_size
      
      chunk_query <- sprintf("
        SELECT 
          estado,
          COUNT(*) as doc_count,
          MAX(data_documento) as latest_date,
          COUNT(DISTINCT tipo) as type_count
        FROM documents
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado
        LIMIT %d OFFSET %d
      ", chunk_size, offset)
      
      chunk_data <- dbGetQuery(conn, chunk_query)
      all_data[[i]] <- chunk_data
      
      # Progress callback
      if (!is.null(callback)) {
        callback(i, chunks, nrow(chunk_data))
      }
      
      # Memory management every 10 chunks
      if (i %% 10 == 0) {
        gc(verbose = FALSE)
      }
    }
    
    # Combine all chunks
    result <- bind_rows(all_data)
    
    # Add coordinates
    result <- result %>%
      left_join(BRAZIL_STATE_COORDS, by = c("estado" = "state_code")) %>%
      filter(!is.na(lat), !is.na(lng))
    
    return(result)
    
  }, error = function(e) {
    cat("Error in progressive_load_geographic_data:", e$message, "\n")
    return(data.frame())
  })
}

# Stratified sampling for large datasets
stratified_sample_documents <- function(data, target_size = 5000, strata_var = "estado") {
  if (is.null(data) || !is.data.frame(data) || nrow(data) <= target_size) {
    return(data)
  }
  
  # Calculate sample size per stratum
  strata_summary <- data %>%
    group_by(!!sym(strata_var)) %>%
    summarise(
      stratum_size = n(),
      stratum_prop = n() / nrow(data),
      .groups = "drop"
    ) %>%
    mutate(
      sample_size = pmax(
        round(target_size * stratum_prop),
        min(3, stratum_size)  # Minimum 3 per stratum if available
      ),
      sample_size = pmin(sample_size, stratum_size)  # Don't exceed stratum size
    )
  
  # Perform stratified sampling
  sampled_data <- data %>%
    group_by(!!sym(strata_var)) %>%
    left_join(strata_summary, by = strata_var) %>%
    slice_sample(n = first(sample_size)) %>%
    ungroup() %>%
    select(-stratum_size, -stratum_prop, -sample_size)
  
  attr(sampled_data, "sampling_info") <- list(
    method = "stratified",
    original_size = nrow(data),
    sample_size = nrow(sampled_data),
    sampling_rate = nrow(sampled_data) / nrow(data)
  )
  
  return(sampled_data)
}

# Create optimized WebGL choropleth map
create_webgl_choropleth <- function(state_data, use_webgl = TRUE, show_sampling_note = FALSE) {
  if (is.null(state_data) || !is.data.frame(state_data) || nrow(state_data) == 0) {
    return(plot_ly() %>%
             add_text(x = 0.5, y = 0.5, text = "No data available") %>%
             layout(xaxis = list(visible = FALSE), yaxis = list(visible = FALSE)))
  }
  
  # Prepare hover text
  state_data <- state_data %>%
    mutate(
      hover_text = paste0(
        "<b>Estado:</b> ", estado, "<br>",
        "<b>Documentos:</b> ", format(doc_count, big.mark = ","), "<br>",
        "<b>Última atualização:</b> ", format(latest_date, "%d/%m/%Y"), "<br>",
        "<b>Tipos de documento:</b> ", type_count
      )
    )
  
  # Determine plot type based on data size and WebGL setting
  plot_type <- if (use_webgl && !is.null(state_data) && is.data.frame(state_data) && nrow(state_data) > 100) "scattergeo" else "scatter"
  
  if (plot_type == "scattergeo") {
    # WebGL-accelerated geographic plot
    p <- plot_ly(
      data = state_data,
      type = "scattergeo",
      mode = "markers+text",
      lon = ~lng,
      lat = ~lat,
      text = ~estado,
      marker = list(
        size = ~sqrt(doc_count) * 2,
        color = ~doc_count,
        colorscale = "Viridis",
        colorbar = list(title = "Documents"),
        line = list(color = "white", width = 1)
      ),
      hovertext = ~hover_text,
      hoverinfo = "text"
    ) %>%
    layout(
      geo = list(
        scope = "south america",
        showland = TRUE,
        landcolor = toRGB("gray95"),
        projection = list(type = "mercator"),
        coastlinecolor = toRGB("gray80"),
        countrycolor = toRGB("gray80"),
        showlakes = FALSE,
        lakecolor = toRGB("gray90"),
        center = list(lon = -55, lat = -15),
        lonaxis = list(range = c(-75, -35)),
        lataxis = list(range = c(-35, 5))
      ),
      title = list(
        text = if (show_sampling_note) 
          "Geographic Distribution (Sample)" 
          else "Geographic Distribution of Legislative Documents",
        font = list(size = 16)
      ),
      margin = list(l = 0, r = 0, t = 40, b = 0)
    )
  } else {
    # Standard scatter plot with map-like positioning
    p <- plot_ly(
      data = state_data,
      type = "scatter",
      mode = "markers+text",
      x = ~lng,
      y = ~lat,
      text = ~estado,
      textposition = "top center",
      marker = list(
        size = ~sqrt(doc_count) * 2,
        color = ~doc_count,
        colorscale = "Viridis",
        colorbar = list(title = "Documents"),
        line = list(color = "white", width = 1)
      ),
      hovertext = ~hover_text,
      hoverinfo = "text"
    ) %>%
    layout(
      xaxis = list(
        title = "",
        showgrid = FALSE,
        showticklabels = FALSE,
        zeroline = FALSE,
        range = c(-75, -35)
      ),
      yaxis = list(
        title = "",
        showgrid = FALSE,
        showticklabels = FALSE,
        zeroline = FALSE,
        range = c(-35, 5)
      ),
      title = list(
        text = if (show_sampling_note) 
          "Geographic Distribution (Sample)" 
          else "Geographic Distribution of Legislative Documents",
        font = list(size = 16)
      ),
      margin = list(l = 0, r = 0, t = 40, b = 0)
    )
  }
  
  # Configure for performance
  p <- p %>% 
    config(
      displayModeBar = FALSE,
      responsive = TRUE,
      toImageButtonOptions = list(
        format = "png",
        filename = "geographic_distribution",
        width = 1200,
        height = 800
      )
    )
  
  return(p)
}

# Cache manager for geographic queries
create_geographic_cache <- function(ttl_seconds = 300) {
  cache_env <- new.env(parent = emptyenv())
  
  list(
    get = function(key) {
      if (exists(key, envir = cache_env)) {
        item <- get(key, envir = cache_env)
        if (Sys.time() - item$timestamp < ttl_seconds) {
          return(item$data)
        } else {
          rm(key, envir = cache_env)
        }
      }
      return(NULL)
    },
    
    set = function(key, value) {
      assign(key, list(data = value, timestamp = Sys.time()), envir = cache_env)
    },
    
    clear = function() {
      rm(list = ls(envir = cache_env), envir = cache_env)
    },
    
    size = function() {
      length(ls(envir = cache_env))
    }
  )
}

# Statistical validation for geographic aggregations
validate_geographic_stats <- function(data, confidence_level = 0.95) {
  min_sample_size <- 5
  
  validated_data <- data %>%
    mutate(
      # Statistical reliability indicators
      statistically_reliable = doc_count >= min_sample_size,
      
      # Confidence intervals
      ci_lower = ifelse(
        doc_count >= min_sample_size,
        doc_count - qnorm((1 + confidence_level) / 2) * sqrt(doc_count),
        doc_count
      ),
      ci_upper = ifelse(
        doc_count >= min_sample_size,
        doc_count + qnorm((1 + confidence_level) / 2) * sqrt(doc_count),
        doc_count
      ),
      
      # Quality indicators
      data_quality = case_when(
        doc_count >= 100 ~ "high",
        doc_count >= 30 ~ "medium",
        doc_count >= min_sample_size ~ "low",
        TRUE ~ "insufficient"
      )
    )
  
  return(validated_data)
}

# Memory-efficient data aggregation
aggregate_geographic_data <- function(pool, filters = list()) {
  cleanup <- monitor_memory("aggregate_geographic")
  on.exit(cleanup(), add = TRUE)
  
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    # Build dynamic query based on filters
    where_clauses <- c("estado IS NOT NULL", "estado != ''")
    
    if (!is.null(filters$date_range)) {
      where_clauses <- c(where_clauses, 
        sprintf("data_documento BETWEEN '%s' AND '%s'", 
                filters$date_range[1], filters$date_range[2]))
    }
    
    if (!is.null(filters$categories) && length(filters$categories) > 0) {
      categories_str <- paste0("'", filters$categories, "'", collapse = ",")
      where_clauses <- c(where_clauses, 
        sprintf("categoria_original IN (%s)", categories_str))
    }
    
    where_clause <- paste(where_clauses, collapse = " AND ")
    
    query <- sprintf("
      SELECT 
        estado,
        COUNT(*) as doc_count,
        MAX(data_documento) as latest_date,
        MIN(data_documento) as first_date,
        COUNT(DISTINCT tipo) as type_count,
        COUNT(DISTINCT categoria_original) as category_count
      FROM documents
      WHERE %s
      GROUP BY estado
      ORDER BY doc_count DESC
    ", where_clause)
    
    result <- dbGetQuery(conn, query)
    
    # Add coordinates and validate
    result <- result %>%
      left_join(BRAZIL_STATE_COORDS, by = c("estado" = "state_code")) %>%
      filter(!is.na(lat), !is.na(lng)) %>%
      validate_geographic_stats()
    
    return(result)
    
  }, error = function(e) {
    cat("Error in aggregate_geographic_data:", e$message, "\n")
    return(data.frame())
  })
}

# Export functions
geographic_optimization_exports <- list(
  progressive_load_geographic_data = progressive_load_geographic_data,
  stratified_sample_documents = stratified_sample_documents,
  create_webgl_choropleth = create_webgl_choropleth,
  create_geographic_cache = create_geographic_cache,
  validate_geographic_stats = validate_geographic_stats,
  aggregate_geographic_data = aggregate_geographic_data,
  BRAZIL_STATE_COORDS = BRAZIL_STATE_COORDS,
  monitor_memory = monitor_memory
)