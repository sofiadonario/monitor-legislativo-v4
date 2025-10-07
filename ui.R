# UI Definition - Monitor Legislativo v4
# ======================================
# Modular User Interface | LGPD Compliant | Brazilian Legal Context

# Load UI utilities
source("R/utils/ui_utils.R", local = FALSE)

# Load UI modules
source("R/modules/search_module.R", local = FALSE)
source("R/modules/geographic_module.R", local = FALSE)
source("R/modules/citation_module.R", local = FALSE)
source("R/modules/export_module.R", local = FALSE)
source("R/modules/admin_module.R", local = FALSE)

#' Main UI Function - Monitor Legislativo v4
#' 
#' Creates the complete user interface for the Brazilian Legislative Monitoring System
#' with modular architecture, authentication support, and mobile-responsive design.
#' 
#' @param request Shiny HTTP request object for OAuth handling
#' @return Complete Shiny UI
ui <- function(request) {
  
  # Check for OAuth callbacks in URL
  query <- parseQueryString(request$QUERY_STRING)
  
  # Handle OAuth callbacks
  if (!is.null(query$code) && !is.null(query$state)) {
    # This is an OAuth callback - we'll handle it in the server
    provider <- if(grepl("google", request$HTTP_REFERER %||% "")) "google" else "microsoft"
    
    return(fluidPage(
      tags$head(
        tags$script(HTML(paste0("
          window.location.href = window.location.origin + window.location.pathname + 
          '?oauth_callback=true&provider=", provider, "&code=", query$code, "&state=", query$state, "';
        ")))
      ),
      div(
        style = "display: flex; justify-content: center; align-items: center; height: 100vh; background: #f8f9fa;",
        div(
          h3("Processando autenticação...", style = "text-align: center; color: #666;"),
          div(class = "spinner-border", role = "status", style = "margin: 20px auto; display: block;")
        )
      )
    ))
  }
  
  # Main UI content - conditional based on authentication
  if (exists("auth_enabled") && auth_enabled) {
    # Authentication-enabled UI
    fluidPage(
      add_custom_styles(),
      # Check authentication status and show appropriate UI
      uiOutput("main_content_ui")
    )
  } else {
    # Standard dashboard (no authentication)
    dashboardPage(
      # Header
      dashboardHeader(
        title = "Monitor Legislativo v4 - Análise Legislativa Brasileira",
        titleWidth = 400
      ),
      
      # Sidebar
      dashboardSidebar(
        width = 250,
        sidebarMenu(
          id = "main_menu",
          menuItem("📊 Painel Executivo", tabName = "executive", icon = icon("chart-line")),
          menuItem("📚 Biblioteca", tabName = "library", icon = icon("book")),
          menuItem("🔍 Busca Avançada", tabName = "search", icon = icon("search")),
          menuItem("📈 Analytics Avançados", tabName = "analytics", icon = icon("chart-area")),
          menuItem("🗺️ Análise Geográfica", tabName = "geographic", icon = icon("map-marked-alt")),
          menuItem("📚 Citações", tabName = "citations", icon = icon("quote-right")),
          menuItem("💾 Exportação", tabName = "export", icon = icon("download")),
          menuItem("🏙️ Análise São Paulo", tabName = "saopaulo", icon = icon("city")),
          menuItem("🧠 Text Analytics", tabName = "nlp", icon = icon("brain")),
          if(exists("monitoring_system_loaded") && monitoring_system_loaded) {
            menuItem("⚙️ Monitoramento", tabName = "monitoring", icon = icon("tachometer-alt"))
          },
          if(exists("auth_enabled") && auth_enabled) {
            menuItem("👥 Administração", tabName = "admin", icon = icon("users-cog"))
          }
        )
      ),
  
      # Body
      dashboardBody(
        # Add custom styles and JavaScript
        add_custom_styles(),
        # Optional: shinyjs integration (graceful degradation if not installed)
        if (requireNamespace("shinyjs", quietly = TRUE)) {
          shinyjs::useShinyjs()
        },
        
        # Custom CSS for Brazilian theme
        tags$head(
          tags$style(HTML("
            .main-header .navbar {
              background-color: #2c3e50 !important;
            }
            .main-header .logo {
              background-color: #2c3e50 !important;
              color: white !important;
              border-right: 1px solid #34495e !important;
            }
            .sidebar-menu > li.active > a {
              background-color: #3498db !important;
              border-left: 3px solid #e74c3c !important;
            }
            .box.box-primary {
              border-top-color: #3498db;
            }
            .box.box-success {
              border-top-color: #27ae60;
            }
            .box.box-warning {
              border-top-color: #f39c12;
            }
            .box.box-danger {
              border-top-color: #e74c3c;
            }
            .value-box {
              margin-bottom: 15px;
            }
            .brazilian-colors {
              background: linear-gradient(135deg, #009c3b 0%, #ffdf00 50%, #002776 100%);
              color: white;
              padding: 10px;
              border-radius: 5px;
              margin-bottom: 15px;
            }
            @media (max-width: 768px) {
              .value-box {
                margin-bottom: 10px;
              }
              .box {
                margin-bottom: 10px;
              }
            }
          "))
        ),
        
        tabItems(
          # Executive Summary Tab
          tabItem(tabName = "executive",
            source("R/ui/executive_tab.R", local = TRUE)$value
          ),
          
          # Library Tab  
          tabItem(tabName = "library",
            source("R/ui/library_tab.R", local = TRUE)$value
          ),
          
          # Advanced Search Tab
          tabItem(tabName = "search",
            fluidRow(
              column(12,
                h2("🔍 Busca Avançada de Documentos Legislativos"),
                p("Interface de busca especializada com filtros avançados e análise semântica.", 
                  style = "color: #7f8c8d; margin-bottom: 30px;")
              )
            ),
            # Use the search module
            searchUI("search_module")
          ),
          
          # Advanced Analytics Tab
          tabItem(tabName = "analytics",
            source("R/ui/analytics_tab.R", local = TRUE)$value
          ),
          
          # Geographic Analysis Tab
          tabItem(tabName = "geographic",
            geographicUI("geographic_module")
          ),
          
          # Citations Tab
          tabItem(tabName = "citations",
            citationUI("citation_module")
          ),
          
          # Export Tab
          tabItem(tabName = "export",
            exportUI("export_module")
          ),
          
          # São Paulo Analysis Tab
          tabItem(tabName = "saopaulo",
            source("R/ui/saopaulo_tab.R", local = TRUE)$value
          ),
          
          # Text Analytics Tab
          tabItem(tabName = "nlp",
            source("R/ui/nlp_tab.R", local = TRUE)$value
          ),
          
          # System Monitoring Tab
          if(exists("monitoring_system_loaded") && monitoring_system_loaded) {
            tabItem(tabName = "monitoring",
              source("R/ui/monitoring_tab.R", local = TRUE)$value
            )
          },
          
          # Administration Tab
          if(exists("auth_enabled") && auth_enabled) {
            tabItem(tabName = "admin",
              adminUI("admin_module")
            )
          }
        )
      )
    )
  }
}

cat("✅ UI definition loaded successfully\n")