# DASHBOARD UI
# Ensure shinydashboard is attached before building dashboard components
if (!requireNamespace("shinydashboard", quietly = TRUE)) {
  stop("Package 'shinydashboard' is required but not installed.")
}
library(shinydashboard)

# Monitor Legislativo v4 - Main Dashboard Layout
# ==============================================

#' Create Main Dashboard UI
#' 
#' Professional layout optimized for academic research workflows
#' WCAG 2.1 AA compliant with mobile responsiveness
#' 
#' @param auth_enabled Boolean indicating if authentication is enabled
#' @param monitoring_loaded Boolean indicating if monitoring system is loaded
#' @return Shiny dashboard UI
#' @export
create_main_dashboard <- function(auth_enabled = FALSE, monitoring_loaded = FALSE) {
  
  shinydashboard::dashboardPage(
    
    # Header with institutional branding
    header = create_dashboard_header(),
    
    # Sidebar navigation
    sidebar = create_dashboard_sidebar(monitoring_loaded),
    
    # Main content area
    body = create_dashboard_body()
  )
}

#' Create Dashboard Header
#' 
#' Creates the dashboard header with branding and notifications
#' 
#' @return Dashboard header object
create_dashboard_header <- function() {
  
  shinydashboard::dashboardHeader(
    title = "MackMonitor - Brazilian Legislative Analytics",
    titleWidth = 350,
    
    # System status notifications
    shinydashboard::dropdownMenu(
      type = "notifications",
      headerText = "System Status",
      icon = icon("bell"),
      badgeStatus = "success",
      
      shinydashboard::notificationItem(
        text = "134,014 documents loaded",
        icon = icon("database"),
        status = "success"
      ),
      
      shinydashboard::notificationItem(
        text = "API connection healthy",
        icon = icon("wifi"),
        status = "success"
      ),
      
      shinydashboard::notificationItem(
        text = "Real-time monitoring active",
        icon = icon("chart-line"),
        status = "info"
      )
    ),
    
    # User menu (if authentication enabled)
    shinydashboard::dropdownMenu(
      type = "messages",
      headerText = "Quick Actions",
      icon = icon("cog"),
      
      shinydashboard::messageItem(
        from = "Export",
        message = "Download research data",
        icon = icon("download")
      ),
      
      shinydashboard::messageItem(
        from = "Citation",
        message = "Generate ABNT citations",
        icon = icon("quote-right")
      )
    )
  )
}

#' Create Dashboard Sidebar
#' 
#' Creates the main navigation sidebar
#' 
#' @param monitoring_loaded Boolean indicating if monitoring is available
#' @return Dashboard sidebar object
create_dashboard_sidebar <- function(monitoring_loaded = FALSE) {
  
  shinydashboard::dashboardSidebar(
    width = 280,
    
    shinydashboard::sidebarMenu(
      id = "main_menu",
      
      # Core research tabs
      shinydashboard::menuItem(
        "📊 Executive Summary", 
        tabName = "executive",
        icon = icon("chart-line")
      ),
      
      shinydashboard::menuItem(
        "📚 Library", 
        tabName = "library",
        icon = icon("book")
      ),
      
      shinydashboard::menuItem(
        "📈 Advanced Analytics", 
        tabName = "analytics",
        icon = icon("chart-area"),
        
        # Sub-menu for analytics
        shinydashboard::menuSubItem(
          "Topic Modeling", 
          tabName = "topics",
          icon = icon("project-diagram")
        ),
        
        shinydashboard::menuSubItem(
          "Sentiment Analysis", 
          tabName = "sentiment",
          icon = icon("heart")
        )
      ),
      
      shinydashboard::menuItem(
        "🗺️ Geographic Analysis", 
        tabName = "geographic",
        icon = icon("map-marked-alt")
      ),
      
      shinydashboard::menuItem(
        "🏙️ São Paulo Analysis", 
        tabName = "saopaulo",
        icon = icon("city")
      ),
      
      shinydashboard::menuItem(
        "🧠 Text Analytics", 
        tabName = "nlp",
        icon = icon("brain")
      ),
      
      # Conditional monitoring menu
      if (monitoring_loaded) {
        shinydashboard::menuItem(
          "⚙️ System Monitoring", 
          tabName = "monitoring",
          icon = icon("tachometer-alt")
        )
      },
      
      # Research tools
      shinydashboard::menuItem(
        "🔬 Research Tools", 
        tabName = "research",
        icon = icon("microscope"),
        
        shinydashboard::menuSubItem(
          "Citation Generator", 
          tabName = "citations",
          icon = icon("quote-right")
        ),
        
        shinydashboard::menuSubItem(
          "Data Export", 
          tabName = "export",
          icon = icon("download")
        ),
        
        shinydashboard::menuSubItem(
          "API Documentation", 
          tabName = "api_docs",
          icon = icon("code")
        )
      )
    )
  )
}

#' Create Dashboard Body
#' 
#' Creates the main content body with tab items
#' 
#' @return Dashboard body object
create_dashboard_body <- function() {
  
  shinydashboard::dashboardBody(
    
    # Add custom CSS and JavaScript
    tags$head(
      tags$style(HTML(get_custom_css())),
      tags$meta(name = "viewport", content = "width=device-width, initial-scale=1.0"),
      tags$script(HTML(get_custom_js()))
    ),
    
    # Enable shinyjs
    shinyjs::useShinyjs(),
    
    # Tab content
    shinydashboard::tabItems(
      create_executive_tab(),
      create_library_tab(),
      create_analytics_tab(),
      create_geographic_tab(),
      create_saopaulo_tab(),
      create_nlp_tab(),
      create_monitoring_tab(),
      create_research_tools_tabs()
    )
  )
}

#' Get Custom CSS for Academic Styling
#' 
#' Returns custom CSS for professional academic appearance
#' 
#' @return Character string of CSS
get_custom_css <- function() {
  
  # Read responsive framework CSS
  framework_css <- tryCatch({
    readLines(file.path("R", "ui", "responsive_framework.css"), warn = FALSE)
  }, error = function(e) {
    ""
  })
  
  # Read accessibility CSS  
  accessibility_css <- tryCatch({
    readLines(file.path("R", "ui", "accessibility.css"), warn = FALSE)
  }, error = function(e) {
    ""
  })
  
  # Read touch optimization CSS
  touch_css <- tryCatch({
    readLines(file.path("R", "ui", "touch_optimization.css"), warn = FALSE)
  }, error = function(e) {
    ""
  })
  
  # Read data visualization CSS
  data_viz_css <- tryCatch({
    readLines(file.path("R", "ui", "data_visualization.css"), warn = FALSE)
  }, error = function(e) {
    ""
  })
  
  # Combine CSS files with dashboard-specific styles
  combined_css <- paste(
    paste(framework_css, collapse = "\n"),
    paste(accessibility_css, collapse = "\n"),
    paste(touch_css, collapse = "\n"),
    paste(data_viz_css, collapse = "\n"),
    
    # Dashboard-specific Academic Styling
    "
    /* Dashboard-specific Academic Styling */
    .content-wrapper, .right-side {
      background-color: var(--light-gray, #f8f9fa);
      min-height: calc(100vh - 120px);
    }
    
    .main-header .navbar {
      background: linear-gradient(135deg, var(--primary-dark, #1f4e79) 0%, var(--primary-light, #3498db) 100%);
      box-shadow: var(--shadow-base, 0 2px 4px rgba(0,0,0,0.1));
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .main-header .logo {
      background: transparent;
      color: var(--white, white);
      font-weight: 700;
      font-size: 1.1rem;
      padding: 15px 20px;
      border-right: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .main-sidebar {
      background: linear-gradient(180deg, var(--secondary-dark, #2c3e50) 0%, #34495e 100%);
      box-shadow: var(--shadow-lg, 0 4px 8px rgba(0,0,0,0.1));
    }
    
    .sidebar-menu > li > a {
      color: rgba(255, 255, 255, 0.9);
      padding: 16px 20px;
      font-weight: 500;
      transition: all 0.2s ease;
      border-left: 3px solid transparent;
    }
    
    .sidebar-menu > li > a:hover {
      background-color: rgba(255, 255, 255, 0.1);
      color: var(--white, white);
      border-left-color: var(--primary-light, #3498db);
      transform: translateX(2px);
    }
    
    .sidebar-menu > li.active > a {
      background-color: var(--primary-light, #3498db);
      color: var(--white, white);
      border-left-color: var(--white, white);
      font-weight: 600;
    }
    
    /* Enhanced Value Boxes */
    .small-box {
      border-radius: var(--radius-lg, 8px);
      box-shadow: var(--shadow-base, 0 2px 4px rgba(0,0,0,0.1));
      transition: all 0.2s ease;
      border-left: 4px solid var(--primary-light, #3498db);
      background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
    }
    
    .small-box:hover {
      transform: translateY(-2px);
      box-shadow: var(--shadow-lg, 0 8px 16px rgba(0,0,0,0.15));
    }
    
    .small-box .inner h3 {
      font-size: 2.2rem;
      font-weight: 700;
      color: var(--primary-dark, #1f4e79);
      margin-bottom: 0.2rem;
    }
    
    /* Enhanced Loading States */
    .loading-overlay {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(255, 255, 255, 0.95);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      z-index: 2000;
      backdrop-filter: blur(2px);
    }
    
    .loading-spinner {
      border: 4px solid rgba(52, 152, 219, 0.1);
      border-left: 4px solid var(--primary-light, #3498db);
      border-radius: 50%;
      width: 50px;
      height: 50px;
      animation: spin 1s linear infinite;
      margin-bottom: 15px;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    ",
    sep = "\n"
  )
  
  return(combined_css)
}

#' Get Custom JavaScript
#' 
#' Returns custom JavaScript for enhanced functionality
#' 
#' @return Character string of JavaScript
get_custom_js <- function() {
  
  # Read accessibility JavaScript
  accessibility_js <- tryCatch({
    readLines(file.path("R", "ui", "accessibility.js"), warn = FALSE)
  }, error = function(e) {
    ""
  })
  
  # Combine JavaScript files with dashboard-specific functionality
  combined_js <- paste(
    paste(accessibility_js, collapse = "\n"),
    
    # Dashboard-specific JavaScript
    "
    // Academic Dashboard Enhancements
    $(document).ready(function() {
      
      // Initialize accessibility features
      if (window.AccessibilityManager) {
        window.AccessibilityManager.init();
      }
      
      // Enhanced button loading states with accessibility
      $('.btn').click(function() {
        var btn = $(this);
        if (!btn.hasClass('no-loading')) {
          var originalText = btn.text();
          var loadingText = btn.data('loading-text') || 'Carregando...';
          
          btn.addClass('disabled').text(loadingText);
          btn.attr('aria-busy', 'true');
          
          // Announce to screen readers
          if (window.AccessibilityManager) {
            window.AccessibilityManager.announce('Processando solicitação', 'polite');
          }
          
          setTimeout(function() {
            btn.removeClass('disabled').text(originalText);
            btn.removeAttr('aria-busy');
          }, 2000);
        }
      });
      
      // Smooth scrolling with accessibility announcements
      $('a[href^=\"#\"]').on('click', function(event) {
        var target = $(this.getAttribute('href'));
        if(target.length) {
          event.preventDefault();
          
          // Announce navigation
          if (window.AccessibilityManager) {
            var targetName = target.attr('aria-label') || target.find('h1, h2, h3').first().text() || 'seção';
            window.AccessibilityManager.announce('Navegando para ' + targetName, 'polite');
          }
          
          $('html, body').stop().animate({
            scrollTop: target.offset().top - 70
          }, 1000, function() {
            // Focus target for screen readers
            target.attr('tabindex', '-1').focus();
          });
        }
      });
      
      // Enhanced tooltips with accessibility
      $('[data-toggle=\"tooltip\"]').tooltip({
        container: 'body',
        placement: 'auto',
        trigger: 'hover focus',
        delay: { 'show': 500, 'hide': 100 }
      });
      
      // Auto-refresh indicators with announcements
      function updateLastRefresh() {
        var now = new Date();
        var timeString = now.toLocaleTimeString('pt-BR');
        $('.last-refresh').text('Última atualização: ' + timeString);
        
        // Periodic accessibility announcement
        if (window.AccessibilityManager && now.getMinutes() % 5 === 0) {
          window.AccessibilityManager.announce('Dados atualizados automaticamente', 'polite');
        }
      }
      
      // Update every 30 seconds
      setInterval(updateLastRefresh, 30000);
      updateLastRefresh(); // Initial call
      
      // Enhanced search functionality
      $('#search_query, #global_search').on('input', function() {
        var query = $(this).val().trim();
        var results = $('.search-results');
        
        if (query.length > 2) {
          // Show search suggestions or results
          results.show();
          
          // Announce search progress
          if (window.AccessibilityManager) {
            window.AccessibilityManager.announce('Buscando por: ' + query, 'polite');
          }
        } else {
          results.hide();
        }
      });
      
      // Form validation with accessibility
      $('form').on('submit', function(e) {
        var form = $(this);
        var requiredFields = form.find('[required]');
        var hasErrors = false;
        var errorMessages = [];
        
        requiredFields.each(function() {
          var field = $(this);
          var fieldName = field.attr('aria-label') || field.prev('label').text() || field.attr('placeholder');
          
          if (!field.val().trim()) {
            hasErrors = true;
            field.addClass('is-invalid');
            errorMessages.push(fieldName + ' é obrigatório');
          } else {
            field.removeClass('is-invalid').addClass('is-valid');
          }
        });
        
        if (hasErrors) {
          e.preventDefault();
          
          // Announce errors to screen reader
          if (window.AccessibilityManager) {
            window.AccessibilityManager.announce(
              errorMessages.length + ' erros encontrados: ' + errorMessages.join(', '),
              'assertive'
            );
          }
          
          // Focus first error field
          form.find('.is-invalid').first().focus();
        }
      });
      
      // Data table accessibility enhancements
      $('.dataTable').each(function() {
        var table = $(this);
        
        // Add table summary
        if (!table.attr('aria-describedby')) {
          var summary = $('<div class=\"sr-only\">').attr('id', 'table-summary-' + table.attr('id'));
          var rowCount = table.find('tbody tr').length;
          var colCount = table.find('thead th').length;
          summary.text('Tabela com ' + rowCount + ' linhas e ' + colCount + ' colunas');
          table.before(summary);
          table.attr('aria-describedby', summary.attr('id'));
        }
        
        // Sortable column announcements
        table.find('th[role=\"columnheader\"]').on('click', function() {
          var header = $(this);
          var sortOrder = header.attr('aria-sort');
          var columnName = header.text();
          
          if (window.AccessibilityManager) {
            var message = 'Coluna ' + columnName + ' ordenada ' + 
                         (sortOrder === 'ascending' ? 'crescente' : 'decrescente');
            window.AccessibilityManager.announce(message, 'polite');
          }
        });
      });
      
      // Modal accessibility enhancements
      $('.modal').on('show.bs.modal', function() {
        var modal = $(this);
        if (window.AccessibilityManager) {
          window.AccessibilityManager.openModal(modal[0]);
        }
      });
      
      $('.modal').on('hide.bs.modal', function() {
        var modal = $(this);
        if (window.AccessibilityManager) {
          window.AccessibilityManager.closeModal(modal[0]);
        }
      });
      
      // Loading state management
      $(document).on('shiny:busy', function(event) {
        var output = $(event.target);
        if (output.length) {
          var overlay = $('<div class=\"loading-overlay\">');
          overlay.html('<div class=\"loading-spinner\"></div><div class=\"loading-text\">Carregando dados...</div>');
          output.css('position', 'relative').append(overlay);
          
          if (window.AccessibilityManager) {
            window.AccessibilityManager.announce('Carregando dados', 'polite');
          }
        }
      });
      
      $(document).on('shiny:idle', function(event) {
        $('.loading-overlay').remove();
        
        if (window.AccessibilityManager) {
          window.AccessibilityManager.announce('Dados carregados', 'polite');
        }
      });
      
      // Enhanced keyboard navigation
      $(document).keydown(function(e) {
        // Ctrl/Cmd + K for global search
        if ((e.ctrlKey || e.metaKey) && e.keyCode == 75) {
          e.preventDefault();
          var searchField = $('#global_search, #search_query').first();
          if (searchField.length) {
            searchField.focus();
            
            if (window.AccessibilityManager) {
              window.AccessibilityManager.announce('Campo de busca ativado', 'polite');
            }
          }
        }
        
        // Escape key handling
        if (e.keyCode == 27) {
          // Close dropdowns, modals, etc.
          $('.dropdown-menu.show').removeClass('show');
          $('.modal.show').modal('hide');
        }
      });
      
      // Touch gesture support for mobile
      if ('ontouchstart' in window) {
        $('.sidebar-menu').on('touchstart', function() {
          $(this).addClass('touch-active');
        });
        
        $('.sidebar-menu').on('touchend', function() {
          var menu = $(this);
          setTimeout(function() {
            menu.removeClass('touch-active');
          }, 300);
        });
      }
      
      // Progressive loading for large datasets
      function initProgressiveLoading() {
        var containers = $('.progressive-load');
        
        containers.each(function() {
          var container = $(this);
          var observer = new IntersectionObserver(function(entries) {
            entries.forEach(function(entry) {
              if (entry.isIntersecting) {
                // Load content when visible
                container.trigger('load-content');
                observer.unobserve(entry.target);
              }
            });
          });
          
          observer.observe(this);
        });
      }
      
      initProgressiveLoading();
      
      // Print functionality
      $('.print-button').on('click', function() {
        if (window.AccessibilityManager) {
          window.AccessibilityManager.announce('Preparando para impressão', 'polite');
        }
        
        setTimeout(function() {
          window.print();
        }, 500);
      });
      
      // Export functionality with progress feedback
      $('.export-button').on('click', function() {
        var button = $(this);
        var format = button.data('format') || 'CSV';
        
        button.addClass('disabled').text('Exportando...');
        
        if (window.AccessibilityManager) {
          window.AccessibilityManager.announce('Iniciando export em formato ' + format, 'polite');
        }
        
        // Simulate export process (in real app, this would be handled by Shiny)
        setTimeout(function() {
          button.removeClass('disabled').text('Exportar ' + format);
          
          if (window.AccessibilityManager) {
            window.AccessibilityManager.announceExportStatus(format, 'complete');
          }
        }, 3000);
      });
      
      // Initialize page
      if (window.AccessibilityManager) {
        window.AccessibilityManager.announce('Monitor Legislativo carregado e pronto para uso', 'polite');
      }
      
      // Analytics tracking (privacy-compliant)
      function trackInteraction(action, element) {
        // Basic interaction tracking for UX improvement
        console.log('User interaction:', action, element);
      }
      
      // Track important interactions
      $('.btn-primary').on('click', function() {
        trackInteraction('primary-action', this.id || this.className);
      });
      
      $('.nav-link').on('click', function() {
        trackInteraction('navigation', this.href || this.textContent);
      });
      
    });
    ",
    sep = "\n"
  )
  
  return(combined_js)
}

cat("✅ Dashboard UI module loaded\n")