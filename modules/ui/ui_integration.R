# ===========================================================================
# BRAZILIAN LEGISLATIVE MONITORING SYSTEM - UI INTEGRATION MODULE
# ===========================================================================
# Sprint 4A: Comprehensive UI/UX Enhancement Integration
# Seamless integration of responsive components with existing dashboard
# Government-grade interface with WCAG 2.1 AA compliance
# ===========================================================================

# Load required libraries
library(shiny)
library(shinydashboard)
library(htmltools)
library(shinyjs)

# Source the UI components library
source("modules/ui/components/ui_components.R", local = TRUE)

# ===========================================================================
# UI ENHANCEMENT INITIALIZATION
# ===========================================================================

#' Initialize the enhanced UI system for the legislative monitoring dashboard
#' 
#' This function sets up all the CSS, JavaScript, and component dependencies
#' required for the enhanced UI/UX experience
initialize_enhanced_ui <- function() {
  cat("🚀 Initializing Enhanced UI System for Brazilian Legislative Monitoring\n")
  
  # CSS Dependencies in order of precedence
  ui_dependencies <- list(
    # 1. Responsive Framework (base styles)
    tags$link(
      rel = "stylesheet", 
      type = "text/css", 
      href = "css/responsive-framework.css"
    ),
    
    # 2. Brazilian Government Theme
    tags$link(
      rel = "stylesheet", 
      type = "text/css", 
      href = "css/brazilian-government-theme.css"
    ),
    
    # 3. Accessibility Framework
    tags$link(
      rel = "stylesheet", 
      type = "text/css", 
      href = "css/accessibility.css"
    ),
    
    # 4. JavaScript Components
    tags$script(src = "js/ui-components.js"),
    
    # 5. FontAwesome for icons
    tags$link(
      rel = "stylesheet",
      href = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css",
      integrity = "sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==",
      crossorigin = "anonymous",
      referrerpolicy = "no-referrer"
    ),
    
    # 6. Skip links for accessibility
    div(
      class = "skip-links",
      tags$a(
        href = "#main-content",
        class = "skip-link",
        "Pular para o conteúdo principal"
      ),
      tags$a(
        href = "#sidebar-navigation", 
        class = "skip-link",
        "Pular para a navegação"
      )
    )
  )
  
  # Initialize component system
  initialize_ui_components()
  
  cat("✅ Enhanced UI System initialized successfully\n")
  
  return(ui_dependencies)
}

# ===========================================================================
# ENHANCED DASHBOARD STRUCTURE
# ===========================================================================

#' Create enhanced dashboard page with responsive framework
#' 
#' @param title Dashboard title
#' @param header Custom header content
#' @param sidebar Custom sidebar content
#' @param body Dashboard body content
#' @param enable_auth Whether authentication is enabled
#' 
#' @return Enhanced dashboardPage with accessibility and responsive features
create_enhanced_dashboard <- function(title = "MackMonitor - Brazilian Legislative Analytics",
                                    header = NULL,
                                    sidebar = NULL, 
                                    body = NULL,
                                    enable_auth = FALSE) {
  
  # Initialize UI dependencies
  ui_deps <- initialize_enhanced_ui()
  
  # Default header with government branding
  if (is.null(header)) {
    header <- create_enhanced_header(title, enable_auth)
  }
  
  # Default sidebar with accessibility
  if (is.null(sidebar)) {
    sidebar <- create_enhanced_sidebar()
  }
  
  # Default body with responsive wrapper
  if (is.null(body)) {
    body <- create_enhanced_body()
  }
  
  # Create the enhanced dashboard structure
  fluidPage(
    # HTML head with meta tags and dependencies
    tags$head(
      # Viewport meta tag for mobile responsiveness
      tags$meta(name = "viewport", content = "width=device-width, initial-scale=1, shrink-to-fit=no"),
      
      # Language and accessibility meta tags
      tags$meta(`http-equiv` = "Content-Language", content = "pt-BR"),
      tags$meta(name = "language", content = "Portuguese"),
      tags$meta(name = "robots", content = "noindex, nofollow"), # Government app - no indexing
      
      # Performance hints
      tags$meta(`http-equiv` = "X-UA-Compatible", content = "IE=edge"),
      tags$meta(name = "format-detection", content = "telephone=no"),
      
      # Security headers
      tags$meta(name = "referrer", content = "strict-origin-when-cross-origin"),
      
      # UI dependencies
      ui_deps
    ),
    
    # Enhanced shinyjs for interaction management
    useShinyjs(),
    
    # Main dashboard structure
    dashboardPage(
      header = header,
      sidebar = sidebar,
      body = body,
      skin = "green" # Verde Brasil theme
    ),
    
    # Status announcements for screen readers
    div(id = "sr-announcements", class = "sr-only", `aria-live` = "polite"),
    
    # JavaScript initialization
    tags$script(HTML("
      $(document).ready(function() {
        console.log('🇧🇷 Brazilian Legislative Monitoring System - UI Enhanced');
        
        // Initialize accessibility features
        UIComponents.announceToScreenReader('Sistema de monitoramento legislativo carregado');
        
        // Set focus management
        if (window.location.hash) {
          setTimeout(function() {
            const target = document.querySelector(window.location.hash);
            if (target) {
              target.scrollIntoView();
              if (target.setAttribute) {
                target.setAttribute('tabindex', '-1');
                target.focus();
              }
            }
          }, 100);
        }
        
        // Performance monitoring
        window.addEventListener('load', function() {
          const perfData = performance.timing;
          const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
          console.log('📊 Page load time:', pageLoadTime + 'ms');
          
          if (pageLoadTime > 3000) {
            console.warn('⚠️ Slow page load detected. Consider optimization.');
          }
        });
      });
    "))
  )
}

# ===========================================================================
# ENHANCED HEADER COMPONENT
# ===========================================================================

#' Create enhanced dashboard header with government branding
create_enhanced_header <- function(title, enable_auth = FALSE) {
  
  # Authentication UI elements
  auth_elements <- if (enable_auth) {
    list(
      tags$li(
        class = "dropdown user user-menu",
        tags$a(
          href = "#",
          class = "dropdown-toggle",
          `data-toggle` = "dropdown",
          `aria-haspopup` = "true",
          `aria-expanded` = "false",
          uiOutput("auth_header_ui")
        )
      )
    )
  } else NULL
  
  dashboardHeader(
    title = span(
      class = "header-title",
      tags$img(
        src = "https://www.gov.br/++theme++padrao_govbr/img/govbr-colorido.png",
        alt = "Governo Federal",
        class = "gov-logo",
        style = "height: 30px; margin-right: 10px;"
      ),
      title
    ),
    titleWidth = 400,
    
    # Dropdown menus for user actions
    dropdownMenuOutput("notificationMenu"),
    
    # Mobile navigation toggle (handled by CSS/JS)
    tags$button(
      class = "navbar-toggle d-lg-none",
      type = "button",
      `aria-label` = "Alternar menu de navegação",
      `aria-expanded` = "false",
      span(class = "sr-only", "Toggle navigation"),
      tags$i(class = "fas fa-bars")
    ),
    
    # Authentication elements
    auth_elements
  )
}

# ===========================================================================
# ENHANCED SIDEBAR COMPONENT
# ===========================================================================

#' Create enhanced sidebar with accessibility and responsive features
create_enhanced_sidebar <- function() {
  
  dashboardSidebar(
    id = "sidebar-navigation",
    width = 280,
    
    # Accessibility landmark
    tags$nav(
      `role` = "navigation",
      `aria-label` = "Navegação principal do sistema",
      
      sidebarMenu(
        id = "main-menu",
        
        # Executive Summary - Key Performance Indicators
        menuItem(
          "📊 Resumo Executivo",
          tabName = "executive",
          icon = icon("chart-line"),
          badgeLabel = "Novo",
          badgeColor = "green",
          selected = TRUE
        ),
        
        # Document Library - Advanced Search and Filtering
        menuItem(
          "📚 Biblioteca Legislativa",
          tabName = "library",
          icon = icon("book-open"),
          menuSubItem(
            "Busca Avançada",
            tabName = "library",
            icon = icon("search")
          ),
          menuSubItem(
            "Documentos Recentes",
            tabName = "library_recent",
            icon = icon("clock")
          ),
          menuSubItem(
            "Favoritos",
            tabName = "library_favorites", 
            icon = icon("star")
          )
        ),
        
        # Advanced Analytics - Complex Analysis Tools
        menuItem(
          "📈 Analytics Avançado",
          tabName = "analytics",
          icon = icon("chart-area"),
          menuSubItem(
            "Análise Temporal",
            tabName = "analytics_temporal",
            icon = icon("calendar-alt")
          ),
          menuSubItem(
            "Análise de Texto",
            tabName = "analytics_nlp",
            icon = icon("language")
          ),
          menuSubItem(
            "Correlações",
            tabName = "analytics_correlations",
            icon = icon("project-diagram")
          )
        ),
        
        # Geographic Analysis - Spatial Data Visualization
        menuItem(
          "🗺️ Análise Geográfica",
          tabName = "geographic",
          icon = icon("map-marked-alt"),
          menuSubItem(
            "Mapa por Estados",
            tabName = "geographic_states",
            icon = icon("map")
          ),
          menuSubItem(
            "Análise Municipal",
            tabName = "geographic_cities",
            icon = icon("city")
          ),
          menuSubItem(
            "Distribuição Regional",
            tabName = "geographic_regions",
            icon = icon("globe-americas")
          )
        ),
        
        # Divider for system functions
        br(),
        tags$hr(class = "sidebar-divider"),
        
        # Help and Documentation
        menuItem(
          "❓ Ajuda e Suporte",
          icon = icon("question-circle"),
          href = "#",
          newtab = FALSE,
          tags$a(
            href = "mailto:suporte@mackenzie.br",
            class = "sidebar-link",
            target = "_blank",
            rel = "noopener",
            "Contatar Suporte"
          )
        ),
        
        # Accessibility Settings
        menuItem(
          "♿ Acessibilidade",
          icon = icon("universal-access"),
          tags$div(
            class = "accessibility-controls p-3",
            h5("Configurações de Acessibilidade"),
            
            # High contrast toggle
            div(
              class = "form-check mb-2",
              tags$input(
                type = "checkbox",
                class = "form-check-input",
                id = "high-contrast-toggle"
              ),
              tags$label(
                class = "form-check-label",
                `for` = "high-contrast-toggle",
                "Alto Contraste"
              )
            ),
            
            # Large text toggle
            div(
              class = "form-check mb-2", 
              tags$input(
                type = "checkbox",
                class = "form-check-input",
                id = "large-text-toggle"
              ),
              tags$label(
                class = "form-check-label",
                `for` = "large-text-toggle",
                "Texto Grande"
              )
            ),
            
            # Screen reader mode
            div(
              class = "form-check",
              tags$input(
                type = "checkbox",
                class = "form-check-input", 
                id = "screen-reader-mode"
              ),
              tags$label(
                class = "form-check-label",
                `for` = "screen-reader-mode",
                "Modo Leitor de Tela"
              )
            )
          )
        )
      )
    )
  )
}

# ===========================================================================
# ENHANCED BODY COMPONENT  
# ===========================================================================

#' Create enhanced dashboard body with responsive layout
create_enhanced_body <- function() {
  
  dashboardBody(
    id = "main-content",
    
    # Main content area with ARIA landmark
    tags$main(
      `role` = "main",
      `aria-label` = "Conteúdo principal do sistema",
      
      # Content wrapper for consistent spacing
      div(
        class = "content-wrapper enhanced-content",
        
        # Breadcrumb navigation
        div(
          class = "content-header",
          accessible_breadcrumb(list(
            list(text = "Início", href = "#executive"),
            list(text = "Dashboard", href = NULL) # Current page
          ))
        ),
        
        # Tab items with enhanced structure
        tabItems(
          # Executive Summary Tab - Enhanced with responsive cards
          tabItem(
            tabName = "executive",
            
            # Page header with description
            div(
              class = "page-header mb-4",
              h1("Resumo Executivo", class = "page-title"),
              p(
                class = "page-description text-muted",
                "Visão geral dos indicadores-chave do sistema de monitoramento legislativo brasileiro. ",
                "Dados atualizados em tempo real para suporte à tomada de decisões estratégicas."
              )
            ),
            
            # Loading indicator for initial data load
            loading_indicator(
              text = "Carregando dados do sistema...",
              type = "spinner",
              size = "lg"
            ),
            
            # Executive summary content will be loaded here
            div(id = "executive-content", class = "row"),
            
            # Error container
            div(id = "executive-errors")
          ),
          
          # Library Tab - Enhanced search interface
          tabItem(
            tabName = "library",
            
            div(
              class = "page-header mb-4",
              h1("Biblioteca Legislativa", class = "page-title"),
              p(
                class = "page-description text-muted",
                "Acesso completo aos 134.014 documentos legislativos brasileiros com busca avançada e filtros especializados."
              )
            ),
            
            # Enhanced search interface
            responsive_card(
              title = "Busca Avançada de Documentos",
              icon = "fa-search",
              content = div(
                class = "search-interface",
                # Search components will be loaded here
                div(id = "library-search-content")
              ),
              collapsible = FALSE,
              width = 12
            ),
            
            # Results area
            div(
              id = "library-results",
              class = "mt-4",
              # Results will be loaded here
            )
          ),
          
          # Analytics Tab - Advanced analysis tools
          tabItem(
            tabName = "analytics",
            
            div(
              class = "page-header mb-4",
              h1("Analytics Avançado", class = "page-title"),
              p(
                class = "page-description text-muted",
                "Ferramentas de análise estatística e visualização de dados para insights legislativos profundos."
              )
            ),
            
            # Analytics dashboard content
            div(id = "analytics-content", class = "row")
          ),
          
          # Geographic Tab - Spatial analysis
          tabItem(
            tabName = "geographic",
            
            div(
              class = "page-header mb-4",
              h1("Análise Geográfica", class = "page-title"),
              p(
                class = "page-description text-muted", 
                "Visualização espacial da distribuição de documentos legislativos por regiões, estados e municípios brasileiros."
              )
            ),
            
            # Geographic analysis content
            div(id = "geographic-content", class = "row")
          )
        )
      )
    )
  )
}

# ===========================================================================
# PERFORMANCE MONITORING UTILITIES
# ===========================================================================

#' Monitor UI performance and accessibility
#' 
#' @param session Shiny session object
monitor_ui_performance <- function(session) {
  
  # JavaScript for performance monitoring
  session$sendCustomMessage("performanceMonitor", list(
    script = "
      // Monitor page load performance
      window.addEventListener('load', function() {
        const perfData = performance.timing;
        const metrics = {
          pageLoad: perfData.loadEventEnd - perfData.navigationStart,
          domReady: perfData.domContentLoadedEventEnd - perfData.navigationStart,
          firstPaint: performance.getEntriesByType('paint').find(entry => entry.name === 'first-paint')?.startTime || 0
        };
        
        Shiny.setInputValue('ui_performance_metrics', metrics);
        
        // Check for accessibility issues in debug mode
        if (window.location.search.includes('debug=accessibility')) {
          const issues = UIComponents.runAccessibilityAudit();
          if (issues.length > 0) {
            Shiny.setInputValue('accessibility_issues', issues);
          }
        }
      });
      
      // Monitor for JavaScript errors
      window.addEventListener('error', function(e) {
        Shiny.setInputValue('js_errors', {
          message: e.message,
          filename: e.filename,
          line: e.lineno,
          timestamp: Date.now()
        });
      });
    "
  ))
}

# ===========================================================================
# UTILITY FUNCTIONS
# ===========================================================================

#' Show enhanced loading state for any container
#' 
#' @param session Shiny session object
#' @param container_id ID of the container element
#' @param message Loading message
show_enhanced_loading <- function(session, container_id, message = "Carregando...") {
  session$sendCustomMessage("showLoading", list(
    container = container_id,
    message = message
  ))
}

#' Hide loading state
#' 
#' @param session Shiny session object  
#' @param container_id ID of the container element
hide_enhanced_loading <- function(session, container_id) {
  session$sendCustomMessage("hideLoading", list(
    container = container_id
  ))
}

#' Display enhanced error message
#' 
#' @param session Shiny session object
#' @param container_id ID of the container element
#' @param message Error message
#' @param title Error title
#' @param can_retry Whether user can retry
#' @param retry_callback JavaScript callback for retry
show_enhanced_error <- function(session, 
                               container_id, 
                               message, 
                               title = "Erro",
                               can_retry = FALSE,
                               retry_callback = NULL) {
  session$sendCustomMessage("showError", list(
    container = container_id,
    message = message,
    title = title,
    canRetry = can_retry,
    retryCallback = retry_callback
  ))
}

#' Announce message to screen readers
#' 
#' @param session Shiny session object
#' @param message Message to announce
#' @param priority Priority level ('polite' or 'assertive')
announce_to_screen_reader <- function(session, message, priority = "polite") {
  session$sendCustomMessage("announceToScreenReader", list(
    message = message,
    priority = priority
  ))
}

cat("✅ UI Integration Module loaded successfully\n")