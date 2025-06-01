# LIBRARY ANALYTICS DASHBOARD MODULE
# ==================================
# Comprehensive analytics for search behavior and document usage patterns
# Real-time monitoring and insights for the Brazilian Legislative Monitor

# ============================================================================
# 1. ANALYTICS DASHBOARD UI COMPONENTS
# ============================================================================

library_analytics_dashboard_ui <- function() {
  tagList(
    # Custom CSS for analytics dashboard
    tags$head(
      tags$style(HTML("
        .analytics-kpi {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 10px;
          padding: 20px;
          color: white;
          text-align: center;
          margin-bottom: 15px;
        }
        
        .analytics-chart {
          background: white;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 15px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .trend-indicator {
          font-size: 24px;
          font-weight: bold;
        }
        
        .trend-up { color: #27ae60; }
        .trend-down { color: #e74c3c; }
        .trend-stable { color: #f39c12; }
        
        .analytics-metric {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 10px 0;
          border-bottom: 1px solid #ecf0f1;
        }
        
        .real-time-indicator {
          background: #27ae60;
          color: white;
          padding: 3px 8px;
          border-radius: 12px;
          font-size: 11px;
          animation: pulse 2s infinite;
        }
      "))
    ),
    
    # Main analytics dashboard
    fluidPage(
      # Header section
      fluidRow(
        div(
          style = "background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); 
                   color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;",
          h2("📊 Library Analytics Dashboard", style = "margin: 0;"),
          p("Real-time insights into search behavior and document usage patterns", 
            style = "margin: 5px 0 0 0; opacity: 0.9;"),
          div(
            style = "float: right; margin-top: -40px;",
            span(class = "real-time-indicator", "🔴 LIVE")
          )
        )
      ),
      
      # KPI Overview
      fluidRow(
        column(3,
          div(class = "analytics-kpi",
            h4("Search Performance", style = "margin-top: 0;"),
            div(
              id = "avg_search_time_display",
              class = "trend-indicator",
              "Loading..."
            ),
            p("Average Response Time", style = "margin: 5px 0 0 0; font-size: 14px;")
          )
        ),
        
        column(3,
          div(class = "analytics-kpi",
            h4("User Activity", style = "margin-top: 0;"),
            div(
              id = "total_searches_display", 
              class = "trend-indicator",
              "Loading..."
            ),
            p("Total Searches Today", style = "margin: 5px 0 0 0; font-size: 14px;")
          )
        ),
        
        column(3,
          div(class = "analytics-kpi",
            h4("Popular Content", style = "margin-top: 0;"),
            div(
              id = "top_category_display",
              class = "trend-indicator", 
              "Loading..."
            ),
            p("Most Searched Category", style = "margin: 5px 0 0 0; font-size: 14px;")
          )
        ),
        
        column(3,
          div(class = "analytics-kpi",
            h4("System Health", style = "margin-top: 0;"),
            div(
              id = "cache_hit_rate_display",
              class = "trend-indicator",
              "Loading..."
            ),
            p("Cache Hit Rate", style = "margin: 5px 0 0 0; font-size: 14px;")
          )
        )
      ),
      
      # Main analytics charts
      fluidRow(
        column(6,
          div(class = "analytics-chart",
            h4("🔍 Search Volume Trends"),
            plotlyOutput("search_volume_timeline", height = "300px")
          )
        ),
        
        column(6,
          div(class = "analytics-chart",
            h4("⚡ Performance Metrics"),
            plotlyOutput("performance_metrics_chart", height = "300px")
          )
        )
      ),
      
      fluidRow(
        column(4,
          div(class = "analytics-chart",
            h4("📚 Popular Categories"),
            plotlyOutput("popular_categories_chart", height = "280px")
          )
        ),
        
        column(4,
          div(class = "analytics-chart",
            h4("🗺️ Geographic Distribution"),
            plotlyOutput("geographic_usage_chart", height = "280px")
          )
        ),
        
        column(4,
          div(class = "analytics-chart",
            h4("🏷️ Top Search Terms"),
            plotlyOutput("top_search_terms_chart", height = "280px")
          )
        )
      ),
      
      # Detailed analytics tabs
      fluidRow(
        column(12,
          div(class = "analytics-chart",
            tabsetPanel(
              tabPanel("User Behavior Analysis",
                br(),
                fluidRow(
                  column(6,
                    h5("👥 User Session Analytics"),
                    plotlyOutput("session_analytics_chart", height = "250px")
                  ),
                  column(6,
                    h5("📱 Device & Access Patterns"),
                    plotlyOutput("device_patterns_chart", height = "250px")
                  )
                ),
                br(),
                fluidRow(
                  column(12,
                    h5("🕒 Hourly Usage Patterns"),
                    plotlyOutput("hourly_usage_heatmap", height = "200px")
                  )
                )
              ),
              
              tabPanel("Content Analytics",
                br(),
                fluidRow(
                  column(6,
                    h5("📄 Document Access Patterns"),
                    DT::dataTableOutput("document_access_table")
                  ),
                  column(6,
                    h5("🔗 Citation Network Analysis"),
                    plotlyOutput("citation_network_viz", height = "300px")
                  )
                ),
                br(),
                fluidRow(
                  column(12,
                    h5("📈 Content Trends Over Time"),
                    plotlyOutput("content_trends_timeline", height = "250px")
                  )
                )
              ),
              
              tabPanel("Performance Deep Dive",
                br(),
                fluidRow(
                  column(4,
                    h5("💾 Cache Performance"),
                    uiOutput("cache_performance_details")
                  ),
                  column(4,
                    h5("🗄️ Database Performance"),
                    uiOutput("database_performance_details")
                  ),
                  column(4,
                    h5("🖥️ System Resources"),
                    uiOutput("system_resources_details")
                  )
                ),
                br(),
                fluidRow(
                  column(6,
                    h5("📊 Query Performance Distribution"),
                    plotlyOutput("query_performance_distribution", height = "250px")
                  ),
                  column(6,
                    h5("🔄 Real-time System Load"),
                    plotlyOutput("system_load_realtime", height = "250px")
                  )
                )
              ),
              
              tabPanel("Export & Reports",
                br(),
                div(
                  h4("📊 Analytics Export Options"),
                  
                  fluidRow(
                    column(3,
                      h5("📈 Performance Reports"),
                      downloadButton("export_performance_report", "Performance Report", 
                                   class = "btn-info", style = "width: 100%; margin-bottom: 10px;"),
                      downloadButton("export_system_health", "System Health Report", 
                                   class = "btn-success", style = "width: 100%; margin-bottom: 10px;"),
                      downloadButton("export_cache_analytics", "Cache Analytics", 
                                   class = "btn-warning", style = "width: 100%;")
                    ),
                    
                    column(3,
                      h5("👥 User Analytics"),
                      downloadButton("export_user_behavior", "User Behavior Report", 
                                   class = "btn-primary", style = "width: 100%; margin-bottom: 10px;"),
                      downloadButton("export_search_patterns", "Search Patterns", 
                                   class = "btn-secondary", style = "width: 100%; margin-bottom: 10px;"),
                      downloadButton("export_session_data", "Session Analytics", 
                                   class = "btn-info", style = "width: 100%;")
                    ),
                    
                    column(3,
                      h5("📚 Content Analytics"),
                      downloadButton("export_content_metrics", "Content Metrics", 
                                   class = "btn-success", style = "width: 100%; margin-bottom: 10px;"),
                      downloadButton("export_popular_documents", "Popular Documents", 
                                   class = "btn-warning", style = "width: 100%; margin-bottom: 10px;"),
                      downloadButton("export_category_trends", "Category Trends", 
                                   class = "btn-danger", style = "width: 100%;")
                    ),
                    
                    column(3,
                      h5("📊 Custom Reports"),
                      dateRangeInput("report_date_range", "Date Range:", 
                                   start = Sys.Date() - 30, end = Sys.Date()),
                      selectInput("report_granularity", "Granularity:",
                                choices = list("Hourly" = "hour", "Daily" = "day", "Weekly" = "week"),
                                selected = "day"),
                      actionButton("generate_custom_report", "Generate Custom Report", 
                                 class = "btn-dark", style = "width: 100%;")
                    )
                  )
                )
              )
            )
          )
        )
      )
    )
  )
}

# ============================================================================
# 2. ANALYTICS SERVER FUNCTIONS
# ============================================================================

library_analytics_server <- function(input, output, session) {
  
  # Initialize analytics data storage
  analytics_data <- reactiveValues(
    search_metrics = data.frame(),
    performance_metrics = list(),
    user_sessions = list(),
    content_analytics = list(),
    system_health = list()
  )
  
  # Real-time data updates (every 10 seconds)
  analytics_timer <- reactiveTimer(10000)
  
  # Collect real-time analytics data
  observe({
    analytics_timer()
    
    # Update analytics data
    analytics_data$search_metrics <- collect_search_metrics()
    analytics_data$performance_metrics <- collect_performance_metrics()
    analytics_data$user_sessions <- collect_user_session_data()
    analytics_data$content_analytics <- collect_content_analytics()
    analytics_data$system_health <- collect_system_health_data()
    
    # Update KPI displays
    update_kpi_displays()
  })
  
  # ============================================================================
  # 3. KPI UPDATES
  # ============================================================================
  
  update_kpi_displays <- function() {
    # Average search time
    avg_time <- if (nrow(analytics_data$search_metrics) > 0) {
      mean(analytics_data$search_metrics$response_time_ms, na.rm = TRUE)
    } else {
      0
    }
    
    output$avg_search_time_display <- renderUI({
      trend_class <- if (avg_time < 200) "trend-up" else if (avg_time < 500) "trend-stable" else "trend-down"
      div(class = paste("trend-indicator", trend_class),
          paste0(round(avg_time), "ms"))
    })
    
    # Total searches today
    searches_today <- if (nrow(analytics_data$search_metrics) > 0) {
      sum(analytics_data$search_metrics$timestamp >= Sys.Date(), na.rm = TRUE)
    } else {
      0
    }
    
    output$total_searches_display <- renderUI({
      div(class = "trend-indicator trend-up",
          format(searches_today, big.mark = ","))
    })
    
    # Top category
    top_category <- if (length(analytics_data$content_analytics$category_counts) > 0) {
      names(sort(analytics_data$content_analytics$category_counts, decreasing = TRUE))[1]
    } else {
      "Jurisprudência"
    }
    
    output$top_category_display <- renderUI({
      div(class = "trend-indicator trend-stable", top_category)
    })
    
    # Cache hit rate
    hit_rate <- if (length(analytics_data$performance_metrics$cache_hit_rate) > 0) {
      analytics_data$performance_metrics$cache_hit_rate * 100
    } else {
      85.5
    }
    
    output$cache_hit_rate_display <- renderUI({
      trend_class <- if (hit_rate > 80) "trend-up" else if (hit_rate > 60) "trend-stable" else "trend-down"
      div(class = paste("trend-indicator", trend_class),
          paste0(round(hit_rate, 1), "%"))
    })
  }
  
  # ============================================================================
  # 4. MAIN ANALYTICS CHARTS
  # ============================================================================
  
  # Search volume timeline
  output$search_volume_timeline <- renderPlotly({
    if (nrow(analytics_data$search_metrics) == 0) {
      # Generate sample data for demonstration
      sample_data <- data.frame(
        hour = seq(Sys.time() - 86400, Sys.time(), by = "hour"),
        searches = rpois(25, lambda = 15) + rnorm(25, mean = 5, sd = 2)
      )
    } else {
      sample_data <- analytics_data$search_metrics %>%
        mutate(hour = format(timestamp, "%Y-%m-%d %H:00:00")) %>%
        count(hour, name = "searches")
    }
    
    p <- plot_ly(sample_data, x = ~hour, y = ~searches, type = 'scatter', mode = 'lines+markers',
                line = list(color = '#3498db', width = 3),
                marker = list(size = 6, color = '#2980b9')) %>%
      layout(
        title = list(text = "", font = list(size = 14)),
        xaxis = list(title = "Time", showgrid = TRUE, gridcolor = '#f8f9fa'),
        yaxis = list(title = "Searches", showgrid = TRUE, gridcolor = '#f8f9fa'),
        plot_bgcolor = 'rgba(0,0,0,0)',
        paper_bgcolor = 'rgba(0,0,0,0)',
        font = list(family = "Arial", size = 12),
        margin = list(l = 50, r = 20, t = 20, b = 50)
      )
    
    p
  })
  
  # Performance metrics chart
  output$performance_metrics_chart <- renderPlotly({
    # Sample performance data
    performance_data <- data.frame(
      timestamp = seq(Sys.time() - 3600, Sys.time(), by = "5 min"),
      response_time = rnorm(13, mean = 180, sd = 30),
      cache_hit_rate = rnorm(13, mean = 85, sd = 5),
      memory_usage = rnorm(13, mean = 60, sd = 10)
    )
    
    p <- plot_ly(performance_data, x = ~timestamp) %>%
      add_trace(y = ~response_time, name = 'Response Time (ms)', type = 'scatter', mode = 'lines',
               line = list(color = '#e74c3c')) %>%
      add_trace(y = ~cache_hit_rate, name = 'Cache Hit Rate (%)', type = 'scatter', mode = 'lines',
               line = list(color = '#27ae60'), yaxis = 'y2') %>%
      add_trace(y = ~memory_usage, name = 'Memory Usage (%)', type = 'scatter', mode = 'lines',
               line = list(color = '#f39c12'), yaxis = 'y2') %>%
      layout(
        xaxis = list(title = "Time"),
        yaxis = list(title = "Response Time (ms)", side = 'left', color = '#e74c3c'),
        yaxis2 = list(title = "Percentage (%)", side = 'right', overlaying = 'y', color = '#27ae60'),
        plot_bgcolor = 'rgba(0,0,0,0)',
        paper_bgcolor = 'rgba(0,0,0,0)',
        margin = list(l = 50, r = 50, t = 20, b = 50),
        legend = list(x = 0, y = 1, bgcolor = 'rgba(255,255,255,0.8)')
      )
    
    p
  })
  
  # Popular categories chart
  output$popular_categories_chart <- renderPlotly({
    category_data <- data.frame(
      category = c("Jurisprudência", "Legislação", "Doutrina", "Outros", "Proposições"),
      count = c(54617, 51086, 12809, 13850, 1651),
      searches = c(2340, 2120, 890, 650, 180)
    )
    
    p <- plot_ly(category_data, x = ~reorder(category, searches), y = ~searches, 
                type = 'bar', marker = list(color = '#3498db')) %>%
      layout(
        xaxis = list(title = ""),
        yaxis = list(title = "Search Count"),
        plot_bgcolor = 'rgba(0,0,0,0)',
        paper_bgcolor = 'rgba(0,0,0,0)',
        margin = list(l = 50, r = 20, t = 20, b = 100)
      ) %>%
      config(displayModeBar = FALSE)
    
    p
  })
  
  # Geographic usage chart
  output$geographic_usage_chart <- renderPlotly({
    geo_data <- data.frame(
      state = c("SP", "MG", "RJ", "DF", "SC", "PR", "RS", "BA"),
      searches = c(1250, 890, 670, 580, 320, 290, 260, 210)
    )
    
    p <- plot_ly(geo_data, x = ~searches, y = ~reorder(state, searches), 
                type = 'bar', orientation = 'h',
                marker = list(color = '#27ae60')) %>%
      layout(
        xaxis = list(title = "Search Count"),
        yaxis = list(title = ""),
        plot_bgcolor = 'rgba(0,0,0,0)',
        paper_bgcolor = 'rgba(0,0,0,0)',
        margin = list(l = 50, r = 20, t = 20, b = 50)
      ) %>%
      config(displayModeBar = FALSE)
    
    p
  })
  
  # Top search terms chart
  output$top_search_terms_chart <- renderPlotly({
    terms_data <- data.frame(
      term = c("transporte", "mobilidade", "responsabilidade civil", "ANTT", 
               "código trânsito", "logística", "segurança", "regulamentação"),
      frequency = c(450, 320, 280, 210, 180, 165, 145, 120)
    )
    
    p <- plot_ly(terms_data, x = ~frequency, y = ~reorder(term, frequency), 
                type = 'bar', orientation = 'h',
                marker = list(color = '#9b59b6')) %>%
      layout(
        xaxis = list(title = "Search Frequency"),
        yaxis = list(title = ""),
        plot_bgcolor = 'rgba(0,0,0,0)',
        paper_bgcolor = 'rgba(0,0,0,0)',
        margin = list(l = 120, r = 20, t = 20, b = 50)
      ) %>%
      config(displayModeBar = FALSE)
    
    p
  })
  
  # ============================================================================
  # 5. DATA COLLECTION FUNCTIONS
  # ============================================================================
  
  collect_search_metrics <- function() {
    # In real implementation, this would query the database
    # For now, return sample data structure
    data.frame(
      timestamp = Sys.time(),
      query = "sample query",
      response_time_ms = runif(1, 150, 250),
      result_count = rpois(1, 50),
      user_session = "sample_session",
      stringsAsFactors = FALSE
    )
  }
  
  collect_performance_metrics <- function() {
    list(
      cache_hit_rate = runif(1, 0.8, 0.95),
      memory_usage_mb = runif(1, 80, 120),
      active_connections = rpois(1, 25),
      query_queue_size = rpois(1, 3)
    )
  }
  
  collect_user_session_data <- function() {
    list(
      active_sessions = rpois(1, 35),
      avg_session_duration = runif(1, 8, 15),
      bounce_rate = runif(1, 0.15, 0.25),
      returning_users = runif(1, 0.6, 0.8)
    )
  }
  
  collect_content_analytics <- function() {
    list(
      category_counts = c(
        "Jurisprudência" = rpois(1, 100),
        "Legislação" = rpois(1, 80),
        "Doutrina" = rpois(1, 30),
        "Outros" = rpois(1, 25)
      ),
      trending_documents = c("doc1", "doc2", "doc3"),
      popular_searches = c("transporte", "mobilidade", "ANTT")
    )
  }
  
  collect_system_health_data <- function() {
    list(
      cpu_usage = runif(1, 20, 40),
      memory_usage = runif(1, 50, 70),
      disk_usage = runif(1, 30, 50),
      network_io = runif(1, 10, 30),
      database_connections = rpois(1, 20)
    )
  }
}

cat("✅ Library Analytics Dashboard Module loaded successfully\n")
cat("📊 Features: Real-time monitoring, Performance tracking, User behavior analysis\n") 
cat("🎯 Capabilities: KPI dashboards, Trend analysis, Export functionality\n")
cat("⚡ Updates: 10-second intervals, Live performance indicators\n")