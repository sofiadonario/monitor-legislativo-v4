# PROGRESSIVE LOADING ENHANCEMENT FOR 134K+ DOCUMENTS
# ====================================================
# Enhanced visualization system with progressive loading, WebGL acceleration,
# and performance optimizations for handling large legislative datasets

cat("🚀 Loading Progressive Loading Enhancement System...\n")

# Required libraries with fallbacks
progressive_libs <- c("dplyr", "plotly", "DT", "pool", "DBI", "jsonlite")
for (lib in progressive_libs) {
  if (!require(lib, character.only = TRUE, quietly = TRUE)) {
    cat("⚠️ Missing", lib, "- some features may be limited\n")
  }
}

# PROGRESSIVE LOADING CONFIGURATION
# =================================
PROGRESSIVE_CONFIG <- list(
  # Loading batch sizes for different UI components
  batch_sizes = list(
    initial_load = 500,      # Initial dashboard load
    search_results = 100,    # Search result pagination
    analytics_sample = 2000, # Analytics calculations
    map_visualization = 1000, # Geographic visualizations
    chart_data = 5000,       # Chart data points
    export_full = 50000      # Full data exports (chunked)
  ),
  
  # Performance thresholds
  performance = list(
    max_memory_mb = 1500,    # Railway memory limit consideration
    query_timeout_sec = 30,   # Database query timeout
    render_timeout_sec = 15,  # UI rendering timeout
    cache_ttl_sec = 1800     # Cache time-to-live (30 minutes)
  ),
  
  # WebGL and acceleration settings
  visualization = list(
    use_webgl = TRUE,        # Enable WebGL for large datasets
    scattergl_threshold = 1000, # Switch to scattergl above this point
    heatmap_downsample = 5000,  # Downsample heatmaps above this
    choropleth_optimize = TRUE   # Optimize choropleth rendering
  )
)

# PROGRESSIVE DATA LOADER
# =======================

#' Progressive Document Loader with Smart Batching
#' @param connection Database connection or NULL for CSV fallback
#' @param batch_size Number of documents per batch
#' @param offset Starting offset for pagination
#' @param filters List of filter criteria
#' @param sort_column Column to sort by
#' @param include_summary Include document summaries (memory intensive)
#' @return List with data and metadata
load_documents_progressive <- function(connection = NULL, batch_size = 500, 
                                     offset = 0, filters = NULL, 
                                     sort_column = "data_publicacao", 
                                     include_summary = FALSE) {
  
  start_time <- Sys.time()
  cat("📊 Progressive loading: batch_size =", batch_size, ", offset =", offset, "\n")
  
  tryCatch({
    # Build base query with smart column selection
    base_columns <- c(
      "id", "titulo", "tipo", "data_publicacao", "estado", 
      "authority_level", "fonte", "document_number"
    )
    
    # Add summary columns only if requested (saves memory)
    if (include_summary) {
      base_columns <- c(base_columns, "conteudo", "document_summary")
    }
    
    # Build WHERE clause from filters
    where_conditions <- c()
    if (!is.null(filters)) {
      if (!is.null(filters$date_range)) {
        where_conditions <- c(where_conditions, 
          sprintf("data_publicacao BETWEEN '%s' AND '%s'", 
                 filters$date_range[1], filters$date_range[2]))
      }
      if (!is.null(filters$estado)) {
        where_conditions <- c(where_conditions,
          sprintf("estado IN (%s)", 
                 paste0("'", filters$estado, "'", collapse = ",")))
      }
      if (!is.null(filters$tipo)) {
        where_conditions <- c(where_conditions,
          sprintf("tipo IN (%s)", 
                 paste0("'", filters$tipo, "'", collapse = ",")))
      }
      if (!is.null(filters$search_term)) {
        where_conditions <- c(where_conditions,
          sprintf("(titulo ILIKE '%%%s%%' OR document_summary ILIKE '%%%s%%')",
                 filters$search_term, filters$search_term))
      }
    }
    
    where_clause <- if (length(where_conditions) > 0) {
      paste("WHERE", paste(where_conditions, collapse = " AND "))
    } else {
      ""
    }
    
    # Build complete query
    query <- sprintf(
      "SELECT %s FROM documents %s ORDER BY %s LIMIT %d OFFSET %d",
      paste(base_columns, collapse = ", "),
      where_clause,
      sort_column,
      batch_size,
      offset
    )
    
    # Execute query with fallback
    if (!is.null(connection)) {
      # Database execution
      result <- DBI::dbGetQuery(connection, query)
    } else {
      # CSV fallback - simulate progressive loading
      if (exists("load_robust_dataset")) {
        full_data <- load_robust_dataset()
        # Apply filters if specified
        filtered_data <- full_data
        if (!is.null(filters)) {
          if (!is.null(filters$estado)) {
            filtered_data <- filtered_data[filtered_data$estado %in% filters$estado, ]
          }
          if (!is.null(filters$tipo)) {
            filtered_data <- filtered_data[filtered_data$tipo %in% filters$tipo, ]
          }
          if (!is.null(filters$search_term)) {
            search_match <- grepl(filters$search_term, 
              paste(filtered_data$titulo, filtered_data$document_summary), 
              ignore.case = TRUE)
            filtered_data <- filtered_data[search_match, ]
          }
        }
        
        # Simulate pagination
        end_row <- min(offset + batch_size, nrow(filtered_data))
        start_row <- min(offset + 1, nrow(filtered_data))
        if (start_row <= end_row) {
          result <- filtered_data[start_row:end_row, base_columns[base_columns %in% names(filtered_data)]]
        } else {
          result <- data.frame()
        }
      } else {
        stop("No data source available")
      }
    }
    
    # Calculate metadata
    total_query <- gsub("SELECT.*?FROM", "SELECT COUNT(*) as total FROM", query)
    total_query <- gsub("ORDER BY.*", "", total_query)
    total_query <- gsub("LIMIT.*", "", total_query)
    
    total_count <- if (!is.null(connection)) {
      DBI::dbGetQuery(connection, total_query)$total[1]
    } else {
      nrow(filtered_data)
    }
    
    load_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    list(
      data = result,
      metadata = list(
        batch_size = batch_size,
        offset = offset,
        returned_rows = nrow(result),
        total_rows = total_count,
        has_more = (offset + batch_size) < total_count,
        load_time_sec = round(load_time, 3),
        memory_usage_mb = round(as.numeric(object.size(result)) / 1024^2, 2),
        query = query
      )
    )
    
  }, error = function(e) {
    cat("❌ Progressive loading error:", e$message, "\n")
    list(
      data = data.frame(),
      metadata = list(
        error = e$message,
        batch_size = batch_size,
        offset = offset,
        returned_rows = 0,
        total_rows = 0,
        has_more = FALSE
      )
    )
  })
}

# PROGRESSIVE VISUALIZATION FUNCTIONS
# ===================================

#' Create WebGL-Accelerated Scatter Plot for Large Datasets
#' @param data Data frame with x, y, and optional color/size columns
#' @param x_col X-axis column name
#' @param y_col Y-axis column name
#' @param color_col Color mapping column (optional)
#' @param size_col Size mapping column (optional)
#' @param title Plot title
#' @return plotly object with WebGL acceleration
create_webgl_scatter <- function(data, x_col, y_col, color_col = NULL, 
                                size_col = NULL, title = "Interactive Scatter Plot") {
  
  cat("📈 Creating WebGL scatter plot with", nrow(data), "points\n")
  
  tryCatch({
    # Determine if WebGL should be used
    use_webgl <- nrow(data) >= PROGRESSIVE_CONFIG$visualization$scattergl_threshold &&
                 PROGRESSIVE_CONFIG$visualization$use_webgl
    
    plot_type <- if (use_webgl) "scattergl" else "scatter"
    
    # Prepare plot data
    plot_data <- data
    
    # Create base plot
    p <- plot_ly(
      data = plot_data,
      x = ~get(x_col),
      y = ~get(y_col),
      type = plot_type,
      mode = "markers"
    )
    
    # Add color mapping if specified
    if (!isTRUE(is.null(color_col)) && color_col %in% names(data)) {
      p <- p %>% add_trace(color = ~get(color_col))
    }
    
    # Add size mapping if specified
    if (!isTRUE(is.null(size_col)) && size_col %in% names(data)) {
      p <- p %>% add_trace(size = ~get(size_col))
    }
    
    # Configure layout for performance
    p <- p %>%
      layout(
        title = list(text = title, font = list(size = 16)),
        xaxis = list(title = x_col),
        yaxis = list(title = y_col),
        hovermode = "closest",
        showlegend = !is.null(color_col)
      ) %>%
      config(
        displayModeBar = TRUE,
        scrollZoom = TRUE,
        displaylogo = FALSE,
        modeBarButtonsToRemove = c('pan2d', 'select2d', 'lasso2d'),
        # WebGL-specific optimizations
        plotGlPixelRatio = 1
      )
    
    if (use_webgl) {
      cat("✅ WebGL acceleration enabled for", nrow(data), "points\n")
    } else {
      cat("✅ Standard rendering for", nrow(data), "points\n")
    }
    
    return(p)
    
  }, error = function(e) {
    cat("❌ WebGL scatter plot error:", e$message, "\n")
    return(NULL)
  })
}

#' Create Progressive DataTable with Server-Side Processing
#' @param data Data frame (can be large)
#' @param id HTML element ID for the table
#' @param page_length Initial page length
#' @param scrollX Enable horizontal scrolling
#' @param buttons Enable export buttons
#' @return DT datatable with progressive loading
create_progressive_datatable <- function(data, id = "progressive_table", 
                                       page_length = 50, scrollX = TRUE, 
                                       buttons = TRUE) {
  
  cat("📋 Creating progressive DataTable with", nrow(data), "rows\n")
  
  tryCatch({
    # Optimize columns for display
    display_data <- data
    
    # Truncate long text columns for performance
    text_columns <- sapply(display_data, function(x) is.character(x) && any(nchar(x) > 100, na.rm = TRUE))
    if (any(text_columns)) {
      display_data[text_columns] <- lapply(display_data[text_columns], function(x) {
        ifelse(nchar(x) > 100, paste0(substr(x, 1, 97), "..."), x)
      })
    }
    
    # Configure table options
    table_options <- list(
      pageLength = page_length,
      lengthMenu = list(c(25, 50, 100, 200, -1), c(25, 50, 100, 200, "All")),
      scrollX = scrollX,
      scrollY = "400px",
      processing = TRUE,
      # Server-side processing for very large datasets
      serverSide = nrow(data) > 10000,
      deferRender = TRUE,
      scroller = TRUE,
      # Column definitions
      columnDefs = list(
        list(className = "dt-center", targets = "_all"),
        list(width = "150px", targets = c(0, 1, 2))
      ),
      # Search configuration
      search = list(regex = TRUE, caseInsensitive = TRUE),
      # Responsive design
      responsive = TRUE
    )
    
    # Add export buttons if requested
    if (buttons) {
      table_options$dom <- "Bfrtip"
      table_options$buttons <- list(
        list(extend = "csv", text = "📊 CSV"),
        list(extend = "excel", text = "📈 Excel"),
        list(extend = "pdf", text = "📄 PDF"),
        list(extend = "print", text = "🖨️ Print")
      )
    }
    
    # Create DataTable
    dt <- DT::datatable(
      display_data,
      options = table_options,
      extensions = c("Buttons", "Scroller", "Responsive"),
      rownames = FALSE,
      escape = FALSE,
      class = "display nowrap"
    )
    
    cat("✅ Progressive DataTable created with", nrow(data), "rows\n")
    return(dt)
    
  }, error = function(e) {
    cat("❌ Progressive DataTable error:", e$message, "\n")
    return(DT::datatable(data.frame(Error = "Table creation failed")))
  })
}

#' Create Memory-Efficient Analytics Summary
#' @param connection Database connection
#' @param sample_size Maximum sample size for calculations
#' @return List with analytics data
create_analytics_summary <- function(connection = NULL, sample_size = 5000) {
  
  cat("📊 Creating analytics summary with sample size:", sample_size, "\n")
  
  tryCatch({
    # Load sample data for analytics
    sample_data <- load_documents_progressive(
      connection = connection,
      batch_size = sample_size,
      offset = 0,
      include_summary = FALSE
    )$data
    
    if (nrow(sample_data) == 0) {
      return(list(error = "No data available for analytics"))
    }
    
    # Calculate key metrics efficiently
    analytics <- list(
      total_documents = nrow(sample_data),
      
      # Document type distribution
      document_types = sample_data %>%
        count(tipo, sort = TRUE) %>%
        mutate(percentage = round(n / sum(n) * 100, 1)) %>%
        head(10),
      
      # Geographic distribution  
      geographic_dist = sample_data %>%
        filter(!is.na(estado)) %>%
        count(estado, sort = TRUE) %>%
        mutate(percentage = round(n / sum(n) * 100, 1)) %>%
        head(15),
      
      # Temporal distribution
      temporal_dist = sample_data %>%
        filter(!is.na(data_publicacao)) %>%
        mutate(
          year = as.numeric(format(as.Date(data_publicacao), "%Y")),
          decade = paste0(floor(year / 10) * 10, "s")
        ) %>%
        filter(year >= 1990) %>%  # Focus on recent decades
        count(decade, sort = TRUE),
      
      # Authority level distribution
      authority_dist = sample_data %>%
        filter(!is.na(authority_level)) %>%
        count(authority_level, sort = TRUE) %>%
        mutate(percentage = round(n / sum(n) * 100, 1)),
      
      # Sample metadata
      metadata = list(
        sample_size = nrow(sample_data),
        analysis_timestamp = Sys.time(),
        memory_usage_mb = round(as.numeric(object.size(sample_data)) / 1024^2, 2)
      )
    )
    
    cat("✅ Analytics summary created from", nrow(sample_data), "documents\n")
    return(analytics)
    
  }, error = function(e) {
    cat("❌ Analytics summary error:", e$message, "\n")
    return(list(error = e$message))
  })
}

# ENHANCED CHOROPLETH WITH PROGRESSIVE LOADING
# ============================================

#' Create Progressive Choropleth Map
#' @param connection Database connection
#' @param sample_size Sample size for geographic analysis
#' @param metric_type Type of metric to visualize
#' @return plotly choropleth map
create_progressive_choropleth <- function(connection = NULL, sample_size = 2000, 
                                        metric_type = "count") {
  
  cat("🗺️ Creating progressive choropleth with", sample_size, "sample size\n")
  
  tryCatch({
    # Load geographic data
    geo_data <- load_documents_progressive(
      connection = connection,
      batch_size = sample_size,
      offset = 0,
      include_summary = FALSE
    )$data
    
    if (nrow(geo_data) == 0) {
      return(NULL)
    }
    
    # Prepare state-level aggregation
    state_data <- geo_data %>%
      filter(!is.na(estado), estado != "") %>%
      group_by(estado) %>%
      summarise(
        document_count = n(),
        unique_types = n_distinct(tipo, na.rm = TRUE),
        date_range = paste(
          min(data_publicacao, na.rm = TRUE), 
          "to", 
          max(data_publicacao, na.rm = TRUE)
        ),
        .groups = "drop"
      ) %>%
      # Add Brazilian state information
      mutate(
        state_code = estado,
        state_name = case_when(
          estado == "SP" ~ "São Paulo",
          estado == "RJ" ~ "Rio de Janeiro", 
          estado == "MG" ~ "Minas Gerais",
          estado == "RS" ~ "Rio Grande do Sul",
          estado == "PR" ~ "Paraná",
          estado == "SC" ~ "Santa Catarina",
          estado == "BA" ~ "Bahia",
          estado == "DF" ~ "Distrito Federal",
          TRUE ~ estado
        ),
        # Add coordinates for fallback visualization
        lon = case_when(
          estado == "SP" ~ -46.6333,
          estado == "RJ" ~ -43.1729,
          estado == "MG" ~ -43.9378,
          estado == "RS" ~ -51.2177,
          estado == "PR" ~ -49.2731,
          estado == "SC" ~ -48.5482,
          estado == "BA" ~ -38.5108,
          estado == "DF" ~ -47.8825,
          TRUE ~ -47.0  # Default center
        ),
        lat = case_when(
          estado == "SP" ~ -23.5505,
          estado == "RJ" ~ -22.9068,
          estado == "MG" ~ -19.9208,
          estado == "RS" ~ -30.0346,
          estado == "PR" ~ -25.4284,
          estado == "SC" ~ -27.2423,
          estado == "BA" ~ -12.9714,
          estado == "DF" ~ -15.7942,
          TRUE ~ -14.0  # Default center
        )
      )
    
    # Load geospatial utilities if available
    if (exists("generate_choropleth_map") && exists("init_geospatial_system")) {
      geospatial_system <- init_geospatial_system()
      
      choropleth_map <- generate_choropleth_map(
        state_data = state_data,
        geospatial_system = geospatial_system,
        metric_column = "document_count",
        map_metric = metric_type,
        colorscale = "Viridis",
        show_labels = TRUE,
        opacity = 0.8
      )
      
      if (!is.null(choropleth_map)) {
        return(choropleth_map)
      }
    }
    
    # Fallback to simple scatter map
    cat("🔄 Using fallback scatter visualization\n")
    fallback_map <- create_webgl_scatter(
      data = state_data,
      x_col = "lon",
      y_col = "lat", 
      color_col = "document_count",
      size_col = "document_count",
      title = "Brazilian States - Document Distribution"
    )
    
    return(fallback_map)
    
  }, error = function(e) {
    cat("❌ Progressive choropleth error:", e$message, "\n")
    return(NULL)
  })
}

# PROGRESSIVE LOADING UTILITIES
# =============================

#' Monitor Memory Usage and Performance
#' @return List with memory and performance metrics
monitor_performance <- function() {
  gc_info <- gc()
  list(
    memory_used_mb = sum(gc_info[, "(Mb)"]),
    max_memory_mb = PROGRESSIVE_CONFIG$performance$max_memory_mb,
    memory_usage_pct = round(sum(gc_info[, "(Mb)"]) / PROGRESSIVE_CONFIG$performance$max_memory_mb * 100, 1),
    timestamp = Sys.time()
  )
}

#' Create Performance Dashboard Widget
#' @return Shiny value box with performance metrics
create_performance_widget <- function() {
  perf <- monitor_performance()
  
  color <- if (perf$memory_usage_pct > 80) "red" 
           else if (perf$memory_usage_pct > 60) "yellow" 
           else "green"
  
  valueBox(
    value = paste0(round(perf$memory_used_mb, 0), " MB"),
    subtitle = paste0("Memory Usage (", perf$memory_usage_pct, "%)"),
    icon = icon("memory"),
    color = color,
    width = 3
  )
}

cat("✅ Progressive Loading Enhancement System loaded successfully!\n")
cat("🚀 Features available:\n")
cat("   - Progressive document loading with batching\n")
cat("   - WebGL-accelerated visualizations for large datasets\n") 
cat("   - Memory-efficient DataTables with server-side processing\n")
cat("   - Performance monitoring and optimization\n")
cat("   - Enhanced choropleth mapping with fallbacks\n")
cat("📊 Optimized for Railway deployment with", PROGRESSIVE_CONFIG$performance$max_memory_mb, "MB limit\n")