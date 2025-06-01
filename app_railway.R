# MINIMAL RAILWAY-OPTIMIZED SHINY APPLICATION
# ===========================================
# Production-ready version for Railway deployment
# Progressive loading, robust error recovery, memory-optimized

cat("🚂 Starting Railway-optimized Brazilian Legislative Monitor\n")
cat("=========================================================\n")

# Apply Railway deployment fixes first
source("railway_deployment_fix.R")
apply_railway_deployment_fixes()

# MINIMAL DATA STRUCTURES FOR FALLBACK MODE
# ==========================================
create_fallback_data <- function() {
  # Create minimal sample data if real data loading fails
  list(
    projetos = data.frame(
      id = 1:5,
      numero = paste0("PL ", 1:5, "/2024"),
      ementa = paste("Projeto de Lei", 1:5, "- Dados não disponíveis"),
      situacao = "Em tramitação",
      data_apresentacao = Sys.Date() - (1:5),
      stringsAsFactors = FALSE
    ),
    
    authors = data.frame(
      id = 1:5,
      nome = paste("Deputado", LETTERS[1:5]),
      partido = c("PT", "PSDB", "PL", "MDB", "PP"),
      uf = c("SP", "RJ", "MG", "RS", "PR"),
      stringsAsFactors = FALSE
    ),
    
    status = list(
      total_projetos = 5,
      last_update = Sys.time(),
      data_source = "fallback",
      railway_mode = TRUE
    )
  )
}

# PROGRESSIVE DATA LOADING
# =======================
load_application_data <- function() {
  cat("📊 Loading application data...\n")
  
  data_loaded <- FALSE
  app_data <- NULL
  
  # Try to load real data
  tryCatch({
    if (safe_source("modules/data_loader.R", "Data Loader", required = FALSE)) {
      if (exists("load_legislative_data")) {
        app_data <- load_legislative_data()
        data_loaded <- TRUE
        cat("✅ Real legislative data loaded successfully\n")
      }
    }
  }, error = function(e) {
    cat("⚠️ Real data loading failed:", e$message, "\n")
  })
  
  # Use fallback data if real data failed
  if (!data_loaded || is.null(app_data)) {
    cat("🔄 Using fallback data for demonstration\n")
    app_data <- create_fallback_data()
  }
  
  # Make data globally available
  assign("APP_DATA", app_data, envir = .GlobalEnv)
  
  return(app_data)
}

# MINIMAL UI COMPONENTS
# ====================
create_minimal_ui <- function() {
  
  # Basic sidebar
  sidebar <- dashboardSidebar(
    width = 250,
    sidebarMenu(
      id = "sidebar_menu",
      menuItem("Dashboard", tabName = "dashboard", icon = icon("chart-line")),
      menuItem("Projetos", tabName = "projetos", icon = icon("file-text")),
      menuItem("Análises", tabName = "analises", icon = icon("chart-bar")),
      menuItem("Sistema", tabName = "sistema", icon = icon("cog"))
    )
  )
  
  # Basic body with progressive loading
  body <- dashboardBody(
    
    # Custom CSS for Railway deployment
    tags$head(
      tags$style(HTML("
        .main-header .navbar { background-color: #2c3e50 !important; }
        .main-header .logo { background-color: #34495e !important; }
        .content-wrapper { background-color: #ecf0f1; }
        .box { box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
        .loading-container { 
          text-align: center; 
          padding: 50px; 
          color: #7f8c8d; 
        }
      "))
    ),
    
    tabItems(
      
      # Dashboard Tab
      tabItem(
        tabName = "dashboard",
        fluidRow(
          
          # Status boxes
          valueBoxOutput("total_projetos_box", width = 3),
          valueBoxOutput("tramitacao_box", width = 3),
          valueBoxOutput("aprovados_box", width = 3),
          valueBoxOutput("sistema_status_box", width = 3)
        ),
        
        fluidRow(
          box(
            title = "Resumo Executivo",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            div(
              class = "loading-container",
              h4("Monitor Legislativo Brasileiro"),
              p("Sistema de monitoramento para proposições legislativas"),
              p("Versão otimizada para Railway - Carregamento progressivo ativo"),
              hr(),
              verbatimTextOutput("system_info")
            )
          )
        )
      ),
      
      # Projetos Tab
      tabItem(
        tabName = "projetos",
        fluidRow(
          box(
            title = "Projetos de Lei",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            DT::dataTableOutput("projetos_table")
          )
        )
      ),
      
      # Análises Tab
      tabItem(
        tabName = "analises",
        fluidRow(
          box(
            title = "Análise por Partido",
            status = "primary",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("partido_chart")
          ),
          box(
            title = "Análise por UF",
            status = "primary", 
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("uf_chart")
          )
        )
      ),
      
      # Sistema Tab
      tabItem(
        tabName = "sistema",
        fluidRow(
          box(
            title = "Status do Sistema",
            status = "info",
            solidHeader = TRUE,
            width = 6,
            verbatimTextOutput("deployment_status")
          ),
          box(
            title = "Módulos Carregados",
            status = "info",
            solidHeader = TRUE,
            width = 6,
            verbatimTextOutput("modules_status")
          )
        ),
        
        # Health check (if available)
        conditionalPanel(
          condition = "true",
          fluidRow(
            box(
              title = "Health Check",
              status = "success",
              solidHeader = TRUE,
              width = 12,
              verbatimTextOutput("health_check_output")
            )
          )
        )
      )
    )
  )
  
  # Create dashboard page
  dashboardPage(
    dashboardHeader(title = "Monitor Legislativo BR"),
    sidebar,
    body
  )
}

# MINIMAL SERVER LOGIC
# ===================
create_minimal_server <- function(input, output, session) {
  
  # Reactive data
  app_data <- reactive({
    if (exists("APP_DATA", envir = .GlobalEnv)) {
      return(get("APP_DATA", envir = .GlobalEnv))
    } else {
      return(create_fallback_data())
    }
  })
  
  # Value boxes
  output$total_projetos_box <- renderValueBox({
    data <- app_data()
    valueBox(
      value = nrow(data$projetos),
      subtitle = "Total de Projetos",
      icon = icon("file-text"),
      color = "blue"
    )
  })
  
  output$tramitacao_box <- renderValueBox({
    data <- app_data()
    em_tramitacao <- sum(data$projetos$situacao == "Em tramitação", na.rm = TRUE)
    valueBox(
      value = em_tramitacao,
      subtitle = "Em Tramitação",
      icon = icon("clock"),
      color = "yellow"
    )
  })
  
  output$aprovados_box <- renderValueBox({
    data <- app_data()
    aprovados <- sum(grepl("aprovado", data$projetos$situacao, ignore.case = TRUE), na.rm = TRUE)
    valueBox(
      value = aprovados,
      subtitle = "Aprovados",
      icon = icon("check"),
      color = "green"
    )
  })
  
  output$sistema_status_box <- renderValueBox({
    status <- if (exists("RAILWAY_DEPLOYMENT_STATUS", envir = .GlobalEnv)) "OK" else "BASIC"
    color <- if (status == "OK") "green" else "orange"
    valueBox(
      value = status,
      subtitle = "Sistema",
      icon = icon("server"),
      color = color
    )
  })
  
  # System information
  output$system_info <- renderText({
    info <- c(
      paste("R Version:", R.version.string),
      paste("Platform:", R.version$platform),
      paste("Railway Mode:", is_railway_environment()),
      paste("Shiny Version:", packageVersion("shiny")),
      paste("Data Source:", app_data()$status$data_source),
      paste("Last Update:", format(app_data()$status$last_update, "%Y-%m-%d %H:%M:%S"))
    )
    paste(info, collapse = "\n")
  })
  
  # Projects table
  output$projetos_table <- DT::renderDataTable({
    DT::datatable(
      app_data()$projetos,
      options = list(
        pageLength = 10,
        scrollX = TRUE,
        dom = 'frtip'
      ),
      filter = 'top'
    )
  })
  
  # Charts with error handling
  output$partido_chart <- renderPlotly({
    tryCatch({
      data <- app_data()
      if (!is.null(data$authors) && nrow(data$authors) > 0) {
        party_counts <- table(data$authors$partido)
        p <- plot_ly(
          x = names(party_counts),
          y = as.numeric(party_counts),
          type = 'bar',
          marker = list(color = '#3498db')
        ) %>%
          layout(
            title = "Projetos por Partido",
            xaxis = list(title = "Partido"),
            yaxis = list(title = "Número de Projetos")
          )
        return(p)
      } else {
        # Fallback chart
        plot_ly() %>%
          add_text(x = 0.5, y = 0.5, text = "Dados não disponíveis", 
                  textfont = list(size = 16, color = "gray")) %>%
          layout(showlegend = FALSE, xaxis = list(visible = FALSE), yaxis = list(visible = FALSE))
      }
    }, error = function(e) {
      plot_ly() %>%
        add_text(x = 0.5, y = 0.5, text = "Erro ao carregar gráfico", 
                textfont = list(size = 16, color = "red")) %>%
        layout(showlegend = FALSE, xaxis = list(visible = FALSE), yaxis = list(visible = FALSE))
    })
  })
  
  output$uf_chart <- renderPlotly({
    tryCatch({
      data <- app_data()
      if (!is.null(data$authors) && nrow(data$authors) > 0) {
        uf_counts <- table(data$authors$uf)
        p <- plot_ly(
          x = names(uf_counts),
          y = as.numeric(uf_counts),
          type = 'bar',
          marker = list(color = '#e74c3c')
        ) %>%
          layout(
            title = "Projetos por UF",
            xaxis = list(title = "Estado"),
            yaxis = list(title = "Número de Projetos")
          )
        return(p)
      } else {
        # Fallback chart
        plot_ly() %>%
          add_text(x = 0.5, y = 0.5, text = "Dados não disponíveis", 
                  textfont = list(size = 16, color = "gray")) %>%
          layout(showlegend = FALSE, xaxis = list(visible = FALSE), yaxis = list(visible = FALSE))
      }
    }, error = function(e) {
      plot_ly() %>%
        add_text(x = 0.5, y = 0.5, text = "Erro ao carregar gráfico", 
                textfont = list(size = 16, color = "red")) %>%
        layout(showlegend = FALSE, xaxis = list(visible = FALSE), yaxis = list(visible = FALSE))
    })
  })
  
  # Deployment status
  output$deployment_status <- renderText({
    if (exists("RAILWAY_DEPLOYMENT_STATUS", envir = .GlobalEnv)) {
      status <- get("RAILWAY_DEPLOYMENT_STATUS", envir = .GlobalEnv)
      info <- c(
        "=== RAILWAY DEPLOYMENT STATUS ===",
        paste("Applied:", status$applied),
        paste("Duration:", round(status$duration_seconds, 2), "seconds"),
        paste("Railway Environment:", status$is_railway),
        paste("Timestamp:", format(status$timestamp, "%Y-%m-%d %H:%M:%S")),
        "",
        "=== PACKAGE STATUS ===",
        paste("Core Packages: ALL LOADED"),
        paste("Optional Packages:", status$packages$optional_count, "of", status$packages$total_optional),
        "",
        "=== MODULE STATUS ===",
        paste("Health Check:", if (status$health_check) "LOADED" else "FALLBACK"),
        paste("Monitoring:", if (status$monitoring$loaded) "LOADED" else "FALLBACK"),
        paste("Authentication:", if (status$auth$loaded) "LOADED" else "FALLBACK"),
        paste("Geospatial:", if (status$geospatial$loaded) "LOADED" else "FALLBACK"),
        paste("Database:", if (status$database$loaded) "LOADED" else "FALLBACK"),
        paste("Data Loader:", if (status$data_loader) "LOADED" else "FALLBACK"),
        paste("UI Modules:", status$ui_modules, "loaded")
      )
      paste(info, collapse = "\n")
    } else {
      "Railway deployment fixes not applied.\nUsing basic configuration."
    }
  })
  
  # Modules status
  output$modules_status <- renderText({
    modules_info <- c()
    
    # Check which functions/objects are available
    available_functions <- c(
      "log_info" = exists("log_info"),
      "perform_health_check" = exists("perform_health_check"),
      "auth_config" = exists("auth_config"),
      "load_legislative_data" = exists("load_legislative_data"),
      "APP_DATA" = exists("APP_DATA", envir = .GlobalEnv),
      "RAILWAY_DEPLOYMENT_STATUS" = exists("RAILWAY_DEPLOYMENT_STATUS", envir = .GlobalEnv)
    )
    
    modules_info <- c(
      "=== AVAILABLE FUNCTIONS ===",
      paste(names(available_functions), ":", ifelse(available_functions, "✅", "❌"))
    )
    
    # Add package information
    key_packages <- c("shiny", "shinydashboard", "DT", "plotly", "dplyr", "sf", "geobr")
    package_status <- sapply(key_packages, function(pkg) {
      requireNamespace(pkg, quietly = TRUE)
    })
    
    modules_info <- c(
      modules_info,
      "",
      "=== KEY PACKAGES ===",
      paste(names(package_status), ":", ifelse(package_status, "✅", "❌"))
    )
    
    paste(modules_info, collapse = "\n")
  })
  
  # Health check output
  output$health_check_output <- renderText({
    tryCatch({
      if (exists("perform_health_check")) {
        health <- perform_health_check(detailed = TRUE)
        if (is.list(health)) {
          info <- c(
            paste("Status:", health$status),
            paste("Service:", health$service),
            paste("Timestamp:", health$timestamp),
            paste("Response Time:", health$response_time_ms, "ms")
          )
          
          if (!is.null(health$checks)) {
            info <- c(info, "", "=== DETAILED CHECKS ===")
            for (check_name in names(health$checks)) {
              check <- health$checks[[check_name]]
              if (is.list(check) && "status" %in% names(check)) {
                info <- c(info, paste(check_name, ":", check$status))
              }
            }
          }
          
          return(paste(info, collapse = "\n"))
        }
      }
      
      "Health check function not available.\nBasic status: Application running normally."
      
    }, error = function(e) {
      paste("Health check error:", e$message)
    })
  })
}

# PROGRESSIVE APPLICATION STARTUP
# ===============================
cat("📱 Building minimal UI...\n")
ui <- create_minimal_ui()

cat("⚙️ Creating server logic...\n")
server <- create_minimal_server

# Load application data
cat("📊 Loading application data...\n")
app_data <- load_application_data()

# Final memory cleanup
gc(verbose = FALSE)

cat("\n🚂 RAILWAY APPLICATION READY\n")
cat("============================\n")
cat("UI: ✅ Created\n")
cat("Server: ✅ Created\n") 
cat("Data: ✅ Loaded (", app_data$status$data_source, "mode )\n")
cat("Memory: ✅ Optimized\n")

if (exists("log_info")) {
  log_info("Railway application startup completed successfully", list(
    data_source = app_data$status$data_source,
    total_projetos = nrow(app_data$projetos)
  ))
}

cat("\n🚀 Starting Shiny application on Railway...\n")

# Get PORT from environment variable (Railway provides this)
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"  # Listen on all interfaces for Railway

cat(sprintf("Starting server on %s:%d\n", host, port))

# Create and run the Shiny app with explicit host and port
shinyApp(ui = ui, server = server, options = list(host = host, port = port))