# ==============================================================================
# MONITOR LEGISLATIVO V4 - PHOENIX REBUILD (v2)
# ==============================================================================
# A rock-solid, monolithic app built for stability.
# This version includes working search functionality and a fix for the UI blur.
# ==============================================================================

# ==============================================================================
# 1. LOAD PACKAGES
# ==============================================================================
suppressPackageStartupMessages({
  library(shiny)
  library(shinythemes)
  library(shinycssloaders)  # Loading indicators
  library(DBI)
  library(RPostgres)
  library(DT)
  library(leaflet)
  library(sf)
  library(ggplot2)
  library(plotly)
  library(data.table)
  library(stringr)
  library(dplyr)  # For advanced visualizations
})

# ==============================================================================
# 1.5 LOAD UTILITY FUNCTIONS
# ==============================================================================
# Load UI utilities for safe rendering
if (file.exists("R/utils/ui_utils.R")) {
  source("R/utils/ui_utils.R")
  cat("✅ UI Utilities loaded\n")
} else {
  cat("⚠️ UI Utilities not found\n")
}

# Load IBGE integration utilities
if (file.exists("R/utils/ibge_integration.R")) {
  source("R/utils/ibge_integration.R")
  cat("✅ IBGE Integration Utilities loaded\n")
} else {
  cat("⚠️ IBGE Integration Utilities not found\n")
}

# Load scalar utilities
if (file.exists("R/utils/scalar_utils.R")) {
  source("R/utils/scalar_utils.R")
  cat("✅ Scalar utilities loaded\n")
} else {
  cat("⚠️ Scalar utilities not found - some features may fail\n")
}

# Load input validation module
if (file.exists("R/security/input_validation.R")) {
  source("R/security/input_validation.R")
  cat("✅ Input validation module loaded\n")
} else {
  cat("⚠️ Input validation module not found\n")
}

# ==============================================================================
# 1.5.5 CONFIGURE SECURITY HEADERS
# ==============================================================================
options(shiny.http.response.filter = function(request, response) {
  response$headers[["X-Frame-Options"]] <- "DENY"
  response$headers[["X-Content-Type-Options"]] <- "nosniff"
  response$headers[["X-XSS-Protection"]] <- "1; mode=block"
  response$headers[["Strict-Transport-Security"]] <- "max-age=31536000; includeSubDomains"
  response$headers[["Content-Security-Policy"]] <- "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline';"
  response$headers[["Referrer-Policy"]] <- "strict-origin-when-cross-origin"
  response
})
cat("✅ Security headers configured\n")

# ==============================================================================
# 1.6 LOAD ENHANCED MODULES
# ==============================================================================
if (file.exists("modules/geographic_enhanced.R")) {
  source("modules/geographic_enhanced.R")
  cat("✅ Enhanced Geographic Module loaded\n")
} else {
  cat("⚠️ Enhanced Geographic Module not found - using basic features\n")
}

# Load Transport Corridor Analysis Module (temporarily disabled - requires shinydashboard)
# if (file.exists("modules/maps/transport_corridor_analysis.R")) {
#   transport_module <- source("modules/maps/transport_corridor_analysis.R")$value
#   cat("✅ Transport Corridor Analysis Module loaded\n")
# } else {
#   cat("⚠️ Transport Corridor Analysis Module not found\n")
transport_module <- NULL
# }

# Load Estado Mapeado Map Visualization Module
if (file.exists("modules/maps/estado_mapeado_ui.R")) {
  source("modules/maps/estado_mapeado_ui.R")
  cat("✅ Estado Mapeado UI Module loaded\n")
} else {
  cat("⚠️ Estado Mapeado UI Module not found\n")
}

if (file.exists("modules/maps/estado_mapeado_server.R")) {
  source("modules/maps/estado_mapeado_server.R")
  cat("✅ Estado Mapeado Server Module loaded\n")
} else {
  cat("⚠️ Estado Mapeado Server Module not found\n")
}

# Load Enhanced Library Module
if (file.exists("R/modules/library_enhanced_module.R")) {
  source("R/modules/library_enhanced_module.R")
  cat("✅ Enhanced Library Module loaded\n")
} else {
  cat("⚠️ Enhanced Library Module not found - using basic features\n")
}

# Load Collection Module
if (file.exists("R/modules/collection_module.R")) {
  source("R/modules/collection_module.R")
  cat("✅ Collection Module loaded\n")
} else {
  cat("⚠️ Collection Module not found\n")
}

# Load Brazilian Geo Integration (geocoding functions)
if (file.exists("R/visualization/brazilian_geo_integration.R")) {
  source("R/visualization/brazilian_geo_integration.R")
  cat("✅ Brazilian Geo Integration (Geocoding) loaded\n")
} else {
  cat("⚠️ Brazilian Geo Integration not found\n")
}

# Load Advanced Visualizations Engine (Priority 6 - PRD Implementation)
if (file.exists("modules/analytics/advanced_visualizations.R")) {
  source("modules/analytics/advanced_visualizations.R")
  cat("✅ Advanced Visualizations Engine loaded\n")
} else {
  cat("⚠️ Advanced Visualizations Engine not found - using basic charts only\n")
}

# Load Readability Analytics Module (Sprint 1 - Foundation)
if (file.exists("modules/analytics/readability_ui.R")) {
  source("modules/analytics/readability_ui.R")
  cat("✅ Readability Analytics UI Module loaded\n")
} else {
  cat("⚠️ Readability Analytics UI Module not found\n")
}

if (file.exists("modules/analytics/readability_server.R")) {
  source("modules/analytics/readability_server.R")
  cat("✅ Readability Analytics Server Module loaded\n")
} else {
  cat("⚠️ Readability Analytics Server Module not found\n")
}

# Load Multi-Jurisdictional Comparison Module (Sprint 1 - Foundation)
if (file.exists("R/analytics/multi_jurisdictional_comparison.R")) {
  source("R/analytics/multi_jurisdictional_comparison.R")
  cat("✅ Multi-Jurisdictional Comparison Module loaded\n")
} else {
  cat("⚠️ Multi-Jurisdictional Comparison Module not found\n")
}

if (file.exists("modules/analytics/jurisdictional_ui.R")) {
  source("modules/analytics/jurisdictional_ui.R")
  cat("✅ Jurisdictional Comparison UI Module loaded\n")
} else {
  cat("⚠️ Jurisdictional Comparison UI Module not found\n")
}

if (file.exists("modules/analytics/jurisdictional_server.R")) {
  source("modules/analytics/jurisdictional_server.R")
  cat("✅ Jurisdictional Comparison Server Module loaded\n")
} else {
  cat("⚠️ Jurisdictional Comparison Server Module not found\n")
}

# Load Methodology module
if (file.exists("R/modules/methodology_module.R")) {
  source("R/modules/methodology_module.R")
  cat("✅ Methodology module loaded\n")
} else {
  cat("⚠️ Methodology module not found\n")
}

# Load Text Reuse Detection (LSH) Module (Sprint 1 - Foundation)
if (file.exists("R/analytics/text_reuse_lsh.R")) {
  source("R/analytics/text_reuse_lsh.R")
  cat("✅ Text Reuse Detection (LSH) Module loaded\n")
} else {
  cat("⚠️ Text Reuse Detection Module not found\n")
}

if (file.exists("modules/analytics/text_reuse_ui.R")) {
  source("modules/analytics/text_reuse_ui.R")
  cat("✅ Text Reuse UI Module loaded\n")
} else {
  cat("⚠️ Text Reuse UI Module not found\n")
}

if (file.exists("modules/analytics/text_reuse_server.R")) {
  source("modules/analytics/text_reuse_server.R")
  cat("✅ Text Reuse Server Module loaded\n")
} else {
  cat("⚠️ Text Reuse Server Module not found\n")
}

# Load Network Backbone Extraction Module (Sprint 2 - Network Analytics)
if (file.exists("R/analytics/network_backbone.R")) {
  source("R/analytics/network_backbone.R")
  cat("✅ Network Backbone Module loaded\n")
} else {
  cat("⚠️ Network Backbone Module not found\n")
}

if (file.exists("R/analytics/backbone_visualization.R")) {
  source("R/analytics/backbone_visualization.R")
  cat("✅ Backbone Visualization Module loaded\n")
} else {
  cat("⚠️ Backbone Visualization Module not found\n")
}

if (file.exists("modules/analytics/network_backbone_ui.R")) {
  source("modules/analytics/network_backbone_ui.R")
  cat("✅ Network Backbone UI Module loaded\n")
} else {
  cat("⚠️ Network Backbone UI Module not found\n")
}

if (file.exists("modules/analytics/network_backbone_server.R")) {
  source("modules/analytics/network_backbone_server.R")
  cat("✅ Network Backbone Server Module loaded\n")
} else {
  cat("⚠️ Network Backbone Server Module not found\n")
}

# Load Amendment Pattern Analysis Module (Sprint 2 - Network Analytics)
if (file.exists("R/analytics/amendment_patterns.R")) {
  source("R/analytics/amendment_patterns.R")
  cat("✅ Amendment Pattern Analysis Module loaded\n")
} else {
  cat("⚠️ Amendment Pattern Analysis Module not found\n")
}

# TEMPORARILY DISABLED: Amendment modules load shinydashboard which conflicts with navbarPage
# if (file.exists("modules/analytics/amendment_ui.R")) {
#   source("modules/analytics/amendment_ui.R")
#   cat("✅ Amendment Analysis UI Module loaded\n")
# } else {
#   cat("⚠️ Amendment Analysis UI Module not found\n")
# }
#
# if (file.exists("modules/analytics/amendment_server.R")) {
#   source("modules/analytics/amendment_server.R")
#   cat("✅ Amendment Analysis Server Module loaded\n")
# } else {
#   cat("⚠️ Amendment Analysis Server Module not found\n")
# }

# Load Anomaly Detection Module (Sprint 2 - Network Analytics)
if (file.exists("R/analytics/anomaly_detection.R")) {
  source("R/analytics/anomaly_detection.R")
  cat("✅ Anomaly Detection Module loaded\n")
} else {
  cat("⚠️ Anomaly Detection Module not found\n")
}

if (file.exists("R/analytics/anomaly_scoring.R")) {
  source("R/analytics/anomaly_scoring.R")
  cat("✅ Anomaly Scoring Module loaded\n")
} else {
  cat("⚠️ Anomaly Scoring Module not found\n")
}

if (file.exists("modules/analytics/anomaly_ui.R")) {
  source("modules/analytics/anomaly_ui.R")
  cat("✅ Anomaly Detection UI Module loaded\n")
} else {
  cat("⚠️ Anomaly Detection UI Module not found\n")
}

if (file.exists("modules/analytics/anomaly_server.R")) {
  source("modules/analytics/anomaly_server.R")
  cat("✅ Anomaly Detection Server Module loaded\n")
} else {
  cat("⚠️ Anomaly Detection Server Module not found\n")
}

# Load Semantic Search Module (Sprint 3 - Advanced NLP)
if (file.exists("modules/analytics/semantic_search_ui.R")) {
  source("modules/analytics/semantic_search_ui.R")
  cat("✅ Semantic Search UI Module loaded\n")
} else {
  cat("⚠️ Semantic Search UI Module not found\n")
}

if (file.exists("modules/analytics/semantic_search_server.R")) {
  source("modules/analytics/semantic_search_server.R")
  cat("✅ Semantic Search Server Module loaded\n")
} else {
  cat("⚠️ Semantic Search Server Module not found\n")
}

# Load Topic Explorer Module (Sprint 3 - Advanced NLP)
if (file.exists("modules/analytics/topic_explorer_ui.R")) {
  source("modules/analytics/topic_explorer_ui.R")
  cat("✅ Topic Explorer UI Module loaded\n")
} else {
  cat("⚠️ Topic Explorer UI Module not found\n")
}

if (file.exists("modules/analytics/topic_explorer_server.R")) {
  source("modules/analytics/topic_explorer_server.R")
  cat("✅ Topic Explorer Server Module loaded\n")
} else {
  cat("⚠️ Topic Explorer Server Module not found\n")
}

# Load BERT Precedent Search Module (Sprint 3 - Advanced NLP)
if (file.exists("modules/analytics/bert_precedent_ui.R")) {
  source("modules/analytics/bert_precedent_ui.R")
  cat("✅ BERT Precedent Search UI Module loaded\n")
} else {
  cat("⚠️ BERT Precedent Search UI Module not found\n")
}

if (file.exists("modules/analytics/bert_precedent_server.R")) {
  source("modules/analytics/bert_precedent_server.R")
  cat("✅ BERT Precedent Search Server Module loaded\n")
} else {
  cat("⚠️ BERT Precedent Search Server Module not found\n")
}

# Library Analytics Dashboard Module (Sprint 4 - Phase 2)
if (file.exists("modules/analytics/library_analytics_dashboard.R")) {
  source("modules/analytics/library_analytics_dashboard.R")
  cat("✅ Library Analytics Dashboard Module loaded\n")
} else {
  cat("⚠️ Library Analytics Dashboard Module not found\n")
}

# Network Backbone Extraction Module (Sprint 2 - Network Analytics)
if (file.exists("modules/analytics/network_backbone_ui.R")) {
  source("modules/analytics/network_backbone_ui.R")
  cat("✅ Network Backbone UI Module loaded\n")
} else {
  cat("⚠️ Network Backbone UI Module not found\n")
}

if (file.exists("modules/analytics/network_backbone_server.R")) {
  source("modules/analytics/network_backbone_server.R")
  cat("✅ Network Backbone Server Module loaded\n")
} else {
  cat("⚠️ Network Backbone Server Module not found\n")
}

# Amendment Pattern Analysis Module (Sprint 2 - Network Analytics)
# TEMPORARILY DISABLED: Amendment modules load shinydashboard which conflicts with navbarPage
# if (file.exists("modules/analytics/amendment_ui.R")) {
#   source("modules/analytics/amendment_ui.R")
#   cat("✅ Amendment Pattern UI Module loaded\n")
# } else {
#   cat("⚠️ Amendment Pattern UI Module not found\n")
# }
#
# if (file.exists("modules/analytics/amendment_server.R")) {
#   source("modules/analytics/amendment_server.R")
#   cat("✅ Amendment Pattern Server Module loaded\n")
# } else {
#   cat("⚠️ Amendment Pattern Server Module not found\n")
# }

# Executive Summary Module (Sprint 4 - Phase 2)
if (file.exists("modules/executive_summary_ui.R")) {
  source("modules/executive_summary_ui.R")
  cat("✅ Executive Summary UI Module loaded\n")
} else {
  cat("⚠️ Executive Summary UI Module not found\n")
}

if (file.exists("modules/executive_summary_server.R")) {
  source("modules/executive_summary_server.R")
  cat("✅ Executive Summary Server Module loaded\n")
} else {
  cat("⚠️ Executive Summary Server Module not found\n")
}

if (file.exists("modules/executive_summary_analytics.R")) {
  source("modules/executive_summary_analytics.R")
  cat("✅ Executive Summary Analytics Module loaded\n")
} else {
  cat("⚠️ Executive Summary Analytics Module not found\n")
}

# Executive Export Module (Week 2 - BI Enhancements)
# Only load if dependencies available (pagedown, googleCloudStorageR)
if (file.exists("R/modules/executive_export_module.R")) {
  tryCatch({
    source("R/modules/executive_export_module.R")
    cat("✅ Executive Export Module loaded\n")
  }, error = function(e) {
    cat("⚠️ Executive Export Module failed to load:", e$message, "\n")
    cat("⚠️ PDF/HTML export features will be disabled\n")
  })
} else {
  cat("⚠️ Executive Export Module not found\n")
}

# Anomaly Detection Module (Sprint 2 - Network Analytics)
if (file.exists("modules/analytics/anomaly_ui.R")) {
  source("modules/analytics/anomaly_ui.R")
  cat("✅ Anomaly Detection UI Module loaded\n")
} else {
  cat("⚠️ Anomaly Detection UI Module not found\n")
}

if (file.exists("modules/analytics/anomaly_server.R")) {
  source("modules/analytics/anomaly_server.R")
  cat("✅ Anomaly Detection Server Module loaded\n")
} else {
  cat("⚠️ Anomaly Detection Server Module not found\n")
}

# Sprint 4 - Predictive Analytics Modules
# Survival Analysis Module (Sprint 4 - PRD 4.1)
if (file.exists("modules/analytics/survival_ui.R")) {
  source("modules/analytics/survival_ui.R")
  cat("✅ Survival Analysis UI Module loaded\n")
} else {
  cat("⚠️ Survival Analysis UI Module not found\n")
}

if (file.exists("modules/analytics/survival_server.R")) {
  source("modules/analytics/survival_server.R")
  cat("✅ Survival Analysis Server Module loaded\n")
} else {
  cat("⚠️ Survival Analysis Server Module not found\n")
}

# Voting Prediction Module (Sprint 4 - PRD 4.2)
if (file.exists("modules/analytics/voting_ui.R")) {
  source("modules/analytics/voting_ui.R")
  cat("✅ Voting Prediction UI Module loaded\n")
} else {
  cat("⚠️ Voting Prediction UI Module not found\n")
}

if (file.exists("modules/analytics/voting_server.R")) {
  source("modules/analytics/voting_server.R")
  cat("✅ Voting Prediction Server Module loaded\n")
} else {
  cat("⚠️ Voting Prediction Server Module not found\n")
}

# ==============================================================================
# 2. DATABASE CONNECTION LOGIC (OPTIMIZED WITH CONNECTION POOLING)
# ==============================================================================
# Phase 2: Performance Optimization - Task 2.1 (Connection Pooling)
# Replaced single connection with production-grade connection pool

# Source connection pool manager
source("R/database/pool_manager.R")

# Source query cache system (Phase 2, Task 2.2)
source("R/utils/query_cache.R")

# Source pagination utilities (Phase 2, Task 2.3)
source("R/utils/pagination.R")

# Source query optimizer (Phase 2, Task 2.4)
tryCatch({
  source("R/database/query_optimizer.R")
  cat("✅ Query optimizer loaded\n")
}, error = function(e) {
  cat("⚠️ Query optimizer failed to load:", e$message, "\n")
  cat("⚠️ Continuing without query optimizer\n")
})

# Source security modules (Phase 1: Security Integration)
tryCatch({
  source("R/database/safe_queries.R")
  cat("✅ Safe queries module loaded\n")
}, error = function(e) {
  cat("⚠️ Safe queries failed to load:", e$message, "\n")
})

tryCatch({
  source("R/security/csrf_protection.R")
  cat("✅ CSRF protection loaded\n")
}, error = function(e) {
  cat("⚠️ CSRF protection failed to load:", e$message, "\n")
})

tryCatch({
  source("R/security/security_headers.R")
  cat("✅ Security headers loaded\n")
}, error = function(e) {
  cat("⚠️ Security headers failed to load:", e$message, "\n")
})

# Global connection pool object
db_pool <- NULL
DB_AVAILABLE <- FALSE

# Data extraction date from raw data files (./data_current/README.md)
DATA_EXTRACTION_DATE <- as.Date("2025-10-21")

# Initialize connection pool on app startup
db_pool <- init_db_pool()
DB_AVAILABLE <- !is.null(db_pool) && check_pool_health()

# Create alias for modules that expect secure_db_connection
secure_db_connection <- db_pool

# Initialize query optimizer (Phase 2, Task 2.4)
if (DB_AVAILABLE) {
  optimizer_result <- tryCatch({
    init_database_query_optimizer(
      db_connection = db_pool,
      create_indexes = TRUE,
      enable_monitoring = TRUE
    )
  }, error = function(e) {
    cat("⚠️ Query optimizer initialization failed:", e$message, "\n")
    NULL
  })

  if (!is.null(optimizer_result) && !is.null(optimizer_result$success) && optimizer_result$success) {
    cat("✅ Query optimizer initialized successfully\n")
  } else {
    cat("⚠️ Query optimizer not initialized - continuing without optimization\n")
  }
}

# Check which table name to use
DOCUMENTS_TABLE <- "lexml_documents"  # Default to lexml_documents
if (DB_AVAILABLE) {
  tables <- tryCatch(
    pool::dbListTables(db_pool),
    error = function(e) character(0)
  )

  if ("documents" %in% tables) {
    DOCUMENTS_TABLE <- "documents"
    cat("✅ Using 'documents' table\n")
  } else if ("lexml_documents" %in% tables) {
    DOCUMENTS_TABLE <- "lexml_documents"
    cat("✅ Using 'lexml_documents' table\n")
  } else {
    cat("⚠️ Warning: Neither 'documents' nor 'lexml_documents' table found\n")
    cat("   Available tables:", paste(tables, collapse = ", "), "\n")
  }
}

# Display connection status
if (DB_AVAILABLE) {
  cat("✅ Database connected successfully\n")
} else {
  cat("⚠️ Database not connected. Documents will not be available.\n")
  cat("   To configure database, set these environment variables:\n")
  cat("   PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD\n")
  cat("   Or run: source('setup_local_env.R')\n")
}

# ==============================================================================
# 3. UI DEFINITION (STABLE & MONOLITHIC)
# ==============================================================================
ui <- navbarPage(
  title = "Monitor Legislativo",
  theme = shinytheme("cerulean"), # Re-enabled theme

  # -- Custom CSS and Scripts --
  header = tags$head(
    tags$style(HTML("
      body {
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }

      /* Cookie Consent Banner (Phase 3: LGPD Compliance - Task 3.2) */
      #cookie-consent-banner {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        background-color: #2c3e50;
        color: white;
        padding: 20px;
        box-shadow: 0 -2px 10px rgba(0,0,0,0.2);
        z-index: 9999;
        display: none;
      }

      #cookie-consent-banner.show {
        display: block;
        animation: slideUp 0.3s ease-out;
      }

      @keyframes slideUp {
        from {
          transform: translateY(100%);
        }
        to {
          transform: translateY(0);
        }
      }

      .cookie-content {
        max-width: 1200px;
        margin: 0 auto;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 15px;
      }

      .cookie-text {
        flex: 1;
        min-width: 300px;
      }

      .cookie-buttons {
        display: flex;
        gap: 10px;
      }

      .cookie-btn {
        padding: 10px 20px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-weight: bold;
        transition: background-color 0.2s;
      }

      .cookie-btn.accept {
        background-color: #27ae60;
        color: white;
      }

      .cookie-btn.accept:hover {
        background-color: #229954;
      }

      .cookie-btn.reject {
        background-color: #7f8c8d;
        color: white;
      }

      .cookie-btn.reject:hover {
        background-color: #5d6d7e;
      }
    ")),

    # JS Cookie library for cookie management
    tags$script(src = "https://cdn.jsdelivr.net/npm/js-cookie@3.0.5/dist/js.cookie.min.js"),

    # Cookie consent JavaScript
    tags$script(HTML("
      // Show cookie banner on page load if consent not given
      $(document).on('shiny:connected', function() {
        var cookieConsent = Cookies.get('cookie_consent');
        if (!cookieConsent) {
          $('#cookie-consent-banner').addClass('show');
        }
      });

      // Hide banner function
      Shiny.addCustomMessageHandler('hideCookieBanner', function(message) {
        $('#cookie-consent-banner').removeClass('show');
        setTimeout(function() {
          $('#cookie-consent-banner').css('display', 'none');
        }, 300);
      });
    "))
  ),

  # -- Cookie Consent Banner (Phase 3: LGPD Compliance - Task 3.2) --
  tags$div(
    id = "cookie-consent-banner",
    class = "cookie-consent",
    tags$div(
      class = "cookie-content",
      tags$div(
        class = "cookie-text",
        tags$p(
          style = "margin: 0;",
          HTML("<strong>🍪 Este site utiliza cookies</strong><br>"),
          "Utilizamos cookies essenciais para o funcionamento do site e cookies analíticos para melhorar sua experiência. ",
          tags$a(
            href = "#",
            onclick = "document.querySelectorAll('.navbar-nav a')[document.querySelectorAll('.navbar-nav a').length-2].click(); return false;",
            "Leia nossa Política de Privacidade"
          ),
          " para mais informações."
        )
      ),
      tags$div(
        class = "cookie-buttons",
        tags$button(
          id = "accept_cookies_btn",
          class = "cookie-btn accept",
          onclick = "Shiny.setInputValue('cookie_accept', Math.random()); Cookies.set('cookie_consent', 'accepted', { expires: 365 });",
          "✓ Aceitar Cookies"
        ),
        tags$button(
          id = "reject_cookies_btn",
          class = "cookie-btn reject",
          onclick = "Shiny.setInputValue('cookie_reject', Math.random()); Cookies.set('cookie_consent', 'rejected', { expires: 365 });",
          "✗ Rejeitar Não Essenciais"
        )
      )
    )
  ),

  # -- HOME TAB (EXECUTIVE SUMMARY) --
  tabPanel(
    "Home",
    icon = icon("home"),
    fluidPage(
      h2("Monitor Legislativo - Executive Summary"),
      p("Visão geral da coleção de documentos legislativos brasileiros"),
      hr(),

      # Key Statistics Row
      fluidRow(
        column(3,
          wellPanel(
            style = "background-color: #f0f8ff; text-align: center;",
            h4(icon("file-alt"), " Total Documents"),
            h2(textOutput("home_total_docs", inline = TRUE))
          )
        ),
        column(3,
          wellPanel(
            style = "background-color: #f0fff0; text-align: center;",
            h4(icon("calendar"), " Document Types"),
            h2(textOutput("home_doc_types_count", inline = TRUE))
          )
        ),
        column(3,
          wellPanel(
            style = "background-color: #fff5f0; text-align: center;",
            h4(icon("clock"), " Latest Document"),
            h3(textOutput("home_latest_date", inline = TRUE))
          )
        ),
        column(3,
          wellPanel(
            style = "background-color: #f5f0ff; text-align: center;",
            h4(icon("chart-line"), " Oldest Document"),
            h3(textOutput("home_oldest_date", inline = TRUE))
          )
        )
      ),

      hr(),

      # Document Type Breakdown
      fluidRow(
        column(6,
          wellPanel(
            h4(icon("list"), " Documents by Type"),
            shinycssloaders::withSpinner(
              DT::dataTableOutput("home_type_breakdown"),
              type = 6,
              color = "#3c8dbc"
            )
          )
        ),
        column(6,
          wellPanel(
            h4(icon("calendar-alt"), " Recent Activity (Last 10)"),
            shinycssloaders::withSpinner(
              DT::dataTableOutput("home_recent_activity"),
              type = 6,
              color = "#3c8dbc"
            )
          )
        )
      )
    )
  ),

  # -- EXECUTIVE SUMMARY TAB (SPRINT 4 - PHASE 2) --
  # Module converted to navbarPage-compatible layout (panel_box replaces shinydashboard box)
  tabPanel(
    "Executive Summary",
    icon = icon("dashboard"),
    br(),

    # Export Module (Week 2 - BI Enhancements)
    if (exists("executive_export_ui")) executive_export_ui("executive_export_module"),

    # Executive Summary UI
    executive_summary_ui("executive_summary_module")
  ),

  # -- LIBRARY TAB (ENHANCED) --
  tabPanel(
    "Library",
    icon = icon("book"),
    if (exists("libraryEnhancedUI")) {
      # Use enhanced library module if available
      libraryEnhancedUI("library_enhanced")
    } else {
      # Fallback to basic library tab
      fluidPage(
        h2("Biblioteca de Documentos Legislativos"),
        p("Pesquise, filtre e explore a coleção completa de documentos legislativos brasileiros."),
        hr(),
        wellPanel(
          h4("Filtros de Pesquisa"),
          fluidRow(
            column(6, tags$div(
              textInput("library_search", "Termo de Pesquisa:", placeholder = "Ex: 'tributário' ou 'lei 14.133'"),
              tags$script(HTML("document.getElementById('library_search').setAttribute('maxlength', '500');"))
            )),
            column(3, selectInput("library_tipo", "Tipo de Documento:",
                   choices = c("Todos", "Lei", "Decreto", "Projeto de Lei", "Medida Provisória",
                              "Resolução", "Portaria", "Instrução Normativa", "Parecer",
                              "Acórdão", "Súmula"))),
            column(3, selectInput("library_mostrar", "Mostrar:", choices = c(100, 500, 1000, 5000, 10000, 999999), selected = 100))
          ),
          actionButton("library_apply", "Aplicar Filtros", icon = icon("search")),
          actionButton("library_clear", "Limpar", icon = icon("times"))
        ),
        hr(),
        h4("Resultados da Pesquisa"),
        shinycssloaders::withSpinner(
          DT::dataTableOutput("library_table"),
          type = 6,
          color = "#3c8dbc"
        )
      )
    }
  ),

  # -- GEOGRAPHIC TAB (ENHANCED) --
  tabPanel(
    "Geographic",
    icon = icon("map-marked-alt"),
    fluidPage(
      h1("Geographic Visualization - Enhanced"),
      p("Visualização geográfica avançada de documentos legislativos com múltiplos níveis e modos"),
      div(
        style = "background-color: #f0f8ff; padding: 10px; border-radius: 5px; margin-bottom: 15px;",
        icon("info-circle"),
        strong(" Nota:"),
        " Base de dados atualizada em ",
        strong("21/10/2025"),
        " (data de extração dos dados brutos). ",
        em("Agora com visualização por município, múltiplos modos de análise e corredores de transporte!")
      ),
      hr(),

      # Sub-tabs for different geographic analyses
      tabsetPanel(
        id = "geo_subtabs",
        type = "tabs",

        # TAB 1: Main Choropleth Map
        tabPanel(
          "Mapa Principal",
          icon = icon("map"),
          br(),

      # -- Enhanced Controls Row 1: Visualization Settings --
      wellPanel(
        style = "background-color: #f8f9fa;",
        h4(icon("sliders-h"), " Configurações de Visualização"),
        fluidRow(
          column(3,
            selectInput("geo_viz_mode", "Modo de Visualização:",
                       choices = c(
                         "Total de Documentos" = "absolute",
                         "Docs por 100k Habitantes" = "per_capita",
                         "Docs por km²" = "density",
                         "Atividade Recente" = "temporal"
                       ),
                       selected = "absolute")
          ),
          column(3,
            selectInput("geo_viz_level", "Nível Geográfico:",
                       choices = c(
                         "Estados" = "state",
                         "Municípios (Top 500)" = "municipality"
                       ),
                       selected = "state")
          ),
          column(6,
            div(
              style = "margin-top: 25px;",
              p(
                style = "font-size: 13px; color: #666; margin: 0;",
                icon("lightbulb"),
                strong(" Dica:"),
                " Use o modo 'per_capita' para análise normalizada por população ou 'temporal' para atividade recente."
              )
            )
          )
        )
      ),

      # -- Enhanced Controls Row 2: Data Filters --
      wellPanel(
        style = "background-color: #ffffff;",
        h4(icon("filter"), " Filtros de Dados"),
        fluidRow(
          column(3,
            selectInput("geo_filter_tipo", "Filtrar por Tipo:",
                       choices = c("Todos", "Lei", "Decreto", "Projeto de Lei",
                                  "Medida Provisória", "Resolução", "Portaria",
                                  "Instrução Normativa", "Parecer", "Acórdão", "Súmula"),
                       selected = "Todos")
          ),
          column(4,
            dateRangeInput("geo_date_range", "Período:",
                          start = NULL, end = DATA_EXTRACTION_DATE,
                          format = "dd/mm/yyyy",
                          language = "pt-BR",
                          separator = " até ")
          ),
          column(3,
            div(style = "margin-top: 25px;",
              actionButton("geo_apply", "Aplicar Filtros",
                          class = "btn-primary",
                          icon = icon("check")),
              actionButton("geo_clear", "Limpar",
                          class = "btn-secondary",
                          icon = icon("times"),
                          style = "margin-left: 10px;")
            )
          ),
          column(2,
            div(
              style = "margin-top: 25px;",
              textOutput("geo_stats_summary", inline = TRUE)
            )
          )
        )
      ),

      # -- Enhanced Controls Row 3: Export Options --
      wellPanel(
        style = "background-color: #f8f9fa;",
        h4(icon("download"), " Opções de Exportação"),
        fluidRow(
          column(12,
            div(
              style = "display: flex; gap: 10px; flex-wrap: wrap;",
              downloadButton("geo_download_csv", "CSV",
                           class = "btn-success btn-sm",
                           icon = icon("file-csv")),
              downloadButton("geo_download_geojson", "GeoJSON",
                           class = "btn-success btn-sm",
                           icon = icon("map")),
              downloadButton("geo_download_png", "PNG",
                           class = "btn-info btn-sm",
                           icon = icon("image")),
              downloadButton("geo_download_svg", "SVG",
                           class = "btn-info btn-sm",
                           icon = icon("vector-square")),
              downloadButton("geo_download_pdf", "PDF",
                           class = "btn-info btn-sm",
                           icon = icon("file-pdf")),
              tags$small(
                style = "align-self: center; color: #666; margin-left: 10px;",
                "Exportações incluem dados filtrados e metadados"
              )
            )
          )
        )
      ),

      hr(),

      # -- Map Display with Loading Indicator --
      div(
        style = "position: relative;",
        uiOutput("geo_loading_indicator"),
        leaflet::leafletOutput("geo_map", height = "650px")
      ),

      # -- Statistics Panel --
      hr(),
      wellPanel(
        style = "background-color: #f8f9fa; margin-top: 15px;",
        h4(icon("chart-bar"), " Estatísticas da Visualização"),
        fluidRow(
          column(3,
            div(
              style = "text-align: center; padding: 10px;",
              h3(textOutput("geo_stat_features", inline = TRUE),
                 style = "color: #1e3a8a; margin: 0;"),
              p("Unidades Geográficas", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
            )
          ),
          column(3,
            div(
              style = "text-align: center; padding: 10px;",
              h3(textOutput("geo_stat_documents", inline = TRUE),
                 style = "color: #059669; margin: 0;"),
              p("Total de Documentos", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
            )
          ),
          column(3,
            div(
              style = "text-align: center; padding: 10px;",
              h3(textOutput("geo_stat_avg", inline = TRUE),
                 style = "color: #dc2626; margin: 0;"),
              p("Média por Unidade", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
            )
          ),
          column(3,
            div(
              style = "text-align: center; padding: 10px;",
              h3(textOutput("geo_stat_range", inline = TRUE),
                 style = "color: #ca8a04; margin: 0;"),
              p("Período dos Dados", style = "margin: 5px 0 0 0; color: #666; font-size: 13px;")
            )
          )
        )
      ),

      # -- Data Coverage Info Panel --
      wellPanel(
        style = "background-color: #f0f9ff; border-left: 4px solid #3b82f6; margin-top: 15px;",
        h4(icon("info-circle"), " Cobertura Geográfica dos Dados",
           style = "color: #1e40af; margin-top: 0;"),
        fluidRow(
          column(3,
            div(
              style = "text-align: center; padding: 12px; background-color: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);",
              h3(textOutput("geo_coverage_mapped", inline = TRUE),
                 style = "color: #059669; margin: 5px 0; font-size: 24px;"),
              p("Estaduais", style = "font-size: 12px; color: #666; margin: 0; font-weight: 500;"),
              p("(no mapa)", style = "font-size: 10px; color: #999; margin: 0;")
            )
          ),
          column(3,
            div(
              style = "text-align: center; padding: 12px; background-color: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);",
              h3(textOutput("geo_coverage_federal", inline = TRUE),
                 style = "color: #ea580c; margin: 5px 0; font-size: 24px;"),
              p("Federais", style = "font-size: 12px; color: #666; margin: 0; font-weight: 500;"),
              p("(nacional)", style = "font-size: 10px; color: #999; margin: 0;")
            )
          ),
          column(3,
            div(
              style = "text-align: center; padding: 12px; background-color: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);",
              h3(textOutput("geo_coverage_labor", inline = TRUE),
                 style = "color: #8b5cf6; margin: 5px 0; font-size: 24px;"),
              p("Justiça Trabalho", style = "font-size: 12px; color: #666; margin: 0; font-weight: 500;"),
              p("(regional)", style = "font-size: 10px; color: #999; margin: 0;")
            )
          ),
          column(3,
            div(
              style = "text-align: center; padding: 12px; background-color: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);",
              h3(textOutput("geo_coverage_no_urn", inline = TRUE),
                 style = "color: #64748b; margin: 5px 0; font-size: 24px;"),
              p("Sem URN", style = "font-size: 12px; color: #666; margin: 0; font-weight: 500;"),
              p("(impossível)", style = "font-size: 10px; color: #999; margin: 0;")
            )
          )
        ),
        div(
          style = "margin-top: 15px; padding: 12px; background-color: white; border-radius: 4px;",
          p(icon("lightbulb", style = "color: #3b82f6;"),
            strong(" Por que alguns documentos não aparecem no mapa?"),
            style = "margin: 0 0 10px 0; color: #1e40af; font-size: 14px;"),
          tags$ul(
            style = "font-size: 13px; color: #475569; margin: 0; padding-left: 25px;",
            tags$li(
              tags$strong("Documentos Federais:"),
              " Legislação federal (Congresso, STF, Presidência) aplica-se igualmente a todo o Brasil. Não há variação geográfica específica por estado."
            ),
            tags$li(
              tags$strong("Justiça do Trabalho Regional:"),
              " Tribunais Regionais do Trabalho são órgãos federais que atuam em regiões específicas, não mapeadas por estado individual."
            ),
            tags$li(
              tags$strong("Documentos sem URN:"),
              " Artigos acadêmicos, livros e outras fontes bibliográficas sem URN oficial do LexML."
            )
          )
        )
      ),

      # -- FEDERAL LEGISLATION SECTION --
      hr(),
      wellPanel(
        style = "background-color: #fff8f0; border-left: 4px solid #ea580c; margin-top: 20px;",
        h3(icon("landmark"), " Legislação Federal - Análise Detalhada",
           style = "color: #c2410c; margin-top: 0;"),
        p(
          style = "font-size: 14px; color: #78716c; margin-bottom: 20px;",
          "Documentos federais aplicam-se igualmente a todo o Brasil. Esta seção apresenta análises temporais e por tipo de legislação federal."
        ),

        # Total Count Card
        div(
          style = "background: linear-gradient(135deg, #ea580c 0%, #f97316 100%); padding: 25px; border-radius: 8px; text-align: center; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);",
          h1(textOutput("federal_total_count", inline = TRUE),
             style = "color: white; margin: 0; font-size: 48px; font-weight: 700;"),
          p("Documentos Federais no Sistema",
            style = "color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 16px; font-weight: 500;")
        ),

        # Timeline and Type Breakdown
        fluidRow(
          column(7,
            div(
              style = "background-color: white; padding: 15px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);",
              h4(icon("chart-line"), " Evolução Temporal", style = "color: #ea580c; margin-top: 0;"),
              plotOutput("federal_timeline", height = "350px")
            )
          ),
          column(5,
            div(
              style = "background-color: white; padding: 15px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);",
              h4(icon("chart-pie"), " Tipos de Documentos", style = "color: #ea580c; margin-top: 0;"),
              plotOutput("federal_type_breakdown", height = "350px")
            )
          )
        )
      )
        ), # End of Main Map tabPanel

        # TAB 2: Transport Corridors
        tabPanel(
          "Corredores de Transporte",
          icon = icon("road"),
          br(),
          if (!is.null(transport_module)) {
            transport_module$ui("transport_corridor")
          } else {
            div(
              class = "alert alert-warning",
              icon("exclamation-triangle"),
              " Módulo de Corredores de Transporte não disponível"
            )
          }
        ), # End of Transport Corridors tabPanel

        # TAB 3: Estado Mapeado Geographic Visualization
        tabPanel(
          "Mapa por Estado",
          icon = icon("map-marker-alt"),
          br(),
          if (exists("estadoMapeadoUI")) {
            estadoMapeadoUI("estado_mapeado_map")
          } else {
            div(
              class = "alert alert-warning",
              icon("exclamation-triangle"),
              " Módulo de Visualização por Estado não disponível"
            )
          }
        ) # End of Estado Mapeado tabPanel

      ) # End of tabsetPanel
    ) # End of fluidPage
  ), # End of Geographic tabPanel


  # -- ANALYTICS TAB (Sprints 1-2: All 6 Features) --
  tabPanel(
    "Analytics",
    icon = icon("chart-line"),
    fluidPage(
      h2(icon("chart-line"), " Advanced Analytics"),
      p("Análises avançadas de documentos legislativos brasileiros"),
      hr(),

      tabsetPanel(
        id = "analytics_subtabs",
        type = "pills",

        # Sprint 1 - Foundation Layer
        tabPanel(
          "Legibilidade",
          icon = icon("book-reader"),
          br(),
          readabilityUI("readability_module")
        ),

        tabPanel(
          "Comparação Jurisdicional",
          icon = icon("balance-scale"),
          br(),
          jurisdictionalUI("jurisdictional_comparison")
        ),

        tabPanel(
          "Reuso de Texto",
          icon = icon("copy"),
          br(),
          text_reuse_ui("text_reuse_module")
        ),

        # Sprint 2 - Network Analytics
        tabPanel(
          "Análise de Redes",
          icon = icon("project-diagram"),
          br(),
          network_backbone_ui("network_backbone_module")
        ),

        # TEMPORARILY DISABLED: Amendment module loads shinydashboard which conflicts with navbarPage
        # tabPanel(
        #   "Padrões de Emendas",
        #   icon = icon("edit"),
        #   br(),
        #   amendment_ui("amendment_module")
        # ),

        tabPanel(
          "Detecção de Anomalias",
          icon = icon("exclamation-triangle"),
          br(),
          anomalyUI("anomaly_module")
        ),

        # Sprint 3 - Advanced NLP
        tabPanel(
          "Busca Semântica",
          icon = icon("search"),
          br(),
          semantic_search_ui("semantic_search_module")
        ),

        tabPanel(
          "Explorador de Tópicos",
          icon = icon("lightbulb"),
          br(),
          topic_explorer_ui("topic_explorer_module")
        ),

        tabPanel(
          "Precedentes Jurídicos",
          icon = icon("gavel"),
          br(),
          bert_precedent_ui("bert_precedent_module")
        ),

        # Sprint 4 - Predictive Analytics
        tabPanel(
          "Análise de Sobrevivência",
          icon = icon("chart-line"),
          br(),
          survival_ui("survival_module")
        ),

        tabPanel(
          "Previsão de Votos",
          icon = icon("vote-yea"),
          br(),
          voting_ui("voting_module")
        ),

        # Library Analytics Dashboard (Sprint 4 - Phase 2)
        tabPanel(
          "Analytics da Biblioteca",
          icon = icon("chart-line"),
          br(),
          library_analytics_dashboard_ui()
        ),

        # Basic Visualizations
        tabPanel(
          "Visualizações Básicas",
          icon = icon("chart-simple"),
          br(),
          h3("Estatísticas Gerais"),
          p("Distribuição por tipo e evolução temporal dos documentos"),
          hr(),
          fluidRow(
            column(6, plotOutput("analytics_type_bar", height = "400px")),
            column(6, plotOutput("analytics_month_line", height = "400px"))
          )
        ),

        # Advanced Visualizations
        tabPanel(
          "Visualizações Avançadas",
          icon = icon("project-diagram"),
          br(),
          h3("Análises Multidimensionais"),
          p("Redes, hierarquias e correlações"),
          hr(),

          # Advanced visualization controls
          fluidRow(
            column(3,
              wellPanel(
                h4("Configurações"),
                selectInput(
                  "viz_type",
                  "Tipo de Visualização:",
                  choices = c(
                    "Rede de Citações" = "network",
                    "Mapa de Árvore (Treemap)" = "treemap",
                    "Nuvem de Palavras" = "wordcloud",
                    "Correlações" = "correlation"
                  ),
                  selected = "network"
                ),
                conditionalPanel(
                  condition = "input.viz_type == 'network'",
                  selectInput(
                    "network_layout",
                    "Layout da Rede:",
                    choices = c(
                      "Force Directed" = "force",
                      "Circular" = "circular",
                      "Hierarchical" = "hierarchical"
                    ),
                    selected = "force"
                  )
                ),
                conditionalPanel(
                  condition = "input.viz_type == 'wordcloud'",
                  sliderInput(
                    "wordcloud_max",
                    "Máx. Palavras:",
                    min = 50,
                    max = 200,
                    value = 100
                  )
                ),
                actionButton(
                  "refresh_viz",
                  "Atualizar Visualização",
                  icon = icon("refresh"),
                  class = "btn-primary"
                )
              )
            ),
            column(9,
              # Dynamic visualization output
              conditionalPanel(
                condition = "input.viz_type == 'network'",
                shinycssloaders::withSpinner(
                  htmlOutput("advanced_network_viz"),
                  type = 6,
                  color = "#3c8dbc"
                )
              ),
              conditionalPanel(
                condition = "input.viz_type == 'treemap'",
                shinycssloaders::withSpinner(
                  plotlyOutput("advanced_treemap_viz", height = "600px"),
                  type = 6,
                  color = "#3c8dbc"
                )
              ),
              conditionalPanel(
                condition = "input.viz_type == 'wordcloud'",
                shinycssloaders::withSpinner(
                  htmlOutput("advanced_wordcloud_viz"),
                  type = 6,
                  color = "#3c8dbc"
                )
              ),
              conditionalPanel(
                condition = "input.viz_type == 'correlation'",
                shinycssloaders::withSpinner(
                  plotOutput("advanced_correlation_viz", height = "600px"),
                  type = 6,
                  color = "#3c8dbc"
                )
              )
            )
          ),

          # Additional info
          hr(),
          fluidRow(
            column(12,
              div(
                class = "alert alert-info",
                icon("info-circle"),
                " ",
                strong("Nota:"),
                " As visualizações avançadas requerem pacotes adicionais. ",
                "Se alguma visualização não estiver disponível, instale os pacotes necessários ",
                "listados em data_current/processed/R_analytical_framework/DESCRIPTION."
              )
            )
          )
        )
      ) # End analytics tabsetPanel
    ) # End fluidPage
  ),

  # -- METODOLOGIA TAB --
  tabPanel(
    "Metodologia",
    icon = icon("book-open"),
    methodology_ui("methodology_module")
  ),

  # -- PLACEHOLDER TABS --
  tabPanel("Text Mining", h1("Text Mining"), p("This section is under development.")),

  # -- PRIVACY POLICY TAB (Phase 3: LGPD Compliance - Task 3.5) --
  tabPanel(
    "Política de Privacidade",
    icon = icon("shield-alt"),
    fluidPage(
      style = "max-width: 1200px; margin: auto; padding: 20px;",
      tryCatch({
        if (requireNamespace("markdown", quietly = TRUE)) {
          includeMarkdown("docs/lgpd/privacy_policy_pt.md")
        } else {
          p("Política de Privacidade - Conteúdo temporariamente indisponível")
        }
      }, error = function(e) {
        p("Política de Privacidade - Conteúdo temporariamente indisponível")
      })
    )
  ),

  # -- FOOTER (Phase 3: LGPD Compliance - Task 3.6) --
  footer = tags$footer(
    style = "background-color: #f8f9fa; border-top: 1px solid #dee2e6; padding: 20px; margin-top: 40px; text-align: center;",
    HTML("
      <div style='max-width: 1200px; margin: auto;'>
        <div style='margin-bottom: 10px;'>
          <strong>Monitor Legislativo v4</strong> - Universidade Presbiteriana Mackenzie
        </div>
        <div style='margin-bottom: 10px;'>
          <i class='fa fa-shield-alt'></i> <strong>Encarregado de Proteção de Dados (DPO):</strong>
          <a href='mailto:dpo@mackenzie.br'>dpo@mackenzie.br</a>
        </div>
        <div style='font-size: 0.9em; color: #6c757d;'>
          Para questões sobre privacidade e proteção de dados, entre em contato com nosso DPO.<br>
          <a href='#' onclick='Shiny.setInputValue(\"show_privacy_policy\", Math.random())'>Política de Privacidade</a> |
          <a href='https://www.gov.br/anpd/' target='_blank'>ANPD</a> |
          Em conformidade com a LGPD (Lei nº 13.709/2018)
        </div>
      </div>
    ")
  )
)

# ==============================================================================
# 3.5 SECURITY CONFIGURATION (Phase 1: Security Integration)
# ==============================================================================
# Configure security headers for all HTTP responses

options(shiny.http.response.filter = function(request, response) {
  # Apply security headers
  response$headers[["X-Frame-Options"]] <- "DENY"
  response$headers[["X-Content-Type-Options"]] <- "nosniff"
  response$headers[["X-XSS-Protection"]] <- "1; mode=block"
  response$headers[["Referrer-Policy"]] <- "strict-origin-when-cross-origin"

  # HSTS - Only enable in production with HTTPS
  if (Sys.getenv("ENVIRONMENT") == "production") {
    response$headers[["Strict-Transport-Security"]] <- "max-age=31536000; includeSubDomains"
  }

  # Content Security Policy
  response$headers[["Content-Security-Policy"]] <- paste(
    "default-src 'self';",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com;",
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com;",
    "img-src 'self' data: https: blob:;",
    "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net;",
    "connect-src 'self';",
    "frame-ancestors 'none';"
  )

  response
})

cat("✅ Security headers configured\n")

# ==============================================================================
# 4. SERVER LOGIC (STABLE & MONOLITHIC - v3 with State Machine)
# ==============================================================================
server <- function(input, output, session) {
  # DEBUG: confirm server startup
  cat("=== SERVER FUNCTION STARTED ===\n")

  # ==============================================================================
  # LGPD COMPLIANCE - COOKIE CONSENT (Phase 3: Task 3.2)
  # ==============================================================================

  # Handle cookie acceptance
  observeEvent(input$cookie_accept, {
    cat("✅ User accepted cookies\n")
    session$sendCustomMessage("hideCookieBanner", list())

    # Log consent (if audit logging is enabled)
    if (exists("log_user_action")) {
      tryCatch({
        log_user_action(
          action = "cookie_consent",
          details = list(
            consent_type = "accepted",
            timestamp = Sys.time()
          ),
          session = session
        )
      }, error = function(e) {
        cat("⚠️ Could not log cookie consent:", e$message, "\n")
      })
    }
  })

  # Handle cookie rejection
  observeEvent(input$cookie_reject, {
    cat("⚠️ User rejected non-essential cookies\n")
    session$sendCustomMessage("hideCookieBanner", list())

    # Log consent rejection (if audit logging is enabled)
    if (exists("log_user_action")) {
      tryCatch({
        log_user_action(
          action = "cookie_consent",
          details = list(
            consent_type = "rejected",
            timestamp = Sys.time()
          ),
          session = session
        )
      }, error = function(e) {
        cat("⚠️ Could not log cookie rejection:", e$message, "\n")
      })
    }
  })

  # -- LIBRARY SERVER LOGIC (ENHANCED) --

  # Use enhanced library module if available, otherwise use basic implementation
  if (exists("libraryEnhancedServer")) {
    cat("✅ Initializing Enhanced Library Module\n")
    library_enhanced <- libraryEnhancedServer(
      "library_enhanced",
      db_connection = db_pool,
      db_available = DB_AVAILABLE,
      documents_table = DOCUMENTS_TABLE
    )
  } else {
    cat("⚠️ Enhanced Library Module not available - using basic implementation\n")
  }

  # Initialize Readability Analytics Module (Sprint 1 - Foundation)
  if (exists("readabilityServer")) {
    cat("✅ Initializing Readability Analytics Module\n")
    readability_analytics <- readabilityServer(
      "readability_module",
      db_connection = db_pool,
      db_available = DB_AVAILABLE,
      documents_table = DOCUMENTS_TABLE
    )
  } else {
    cat("⚠️ Readability Analytics Module not available\n")
  }

  # Initialize Multi-Jurisdictional Comparison Module (Sprint 1 - Foundation)
  if (exists("jurisdictionalServer")) {
    cat("✅ Initializing Multi-Jurisdictional Comparison Module\n")
    jurisdictional_comparison <- jurisdictionalServer(
      "jurisdictional_comparison",
      db_connection = db_pool,
      db_available = DB_AVAILABLE,
      documents_table = DOCUMENTS_TABLE
    )
  } else {
    cat("⚠️ Multi-Jurisdictional Comparison Module not available\n")
  }

  # Initialize Text Reuse Detection Module (Sprint 1 - Foundation)
  if (exists("text_reuse_server")) {
    cat("✅ Initializing Text Reuse Detection Module\n")
    text_reuse_module <- text_reuse_server(
      "text_reuse_module",
      db_connection = db_pool
    )
  } else {
    cat("⚠️ Text Reuse Detection Module not available\n")
  }

  # Initialize Network Backbone Module (Sprint 2 - Network Analytics)
  if (exists("network_backbone_server")) {
    cat("✅ Initializing Network Backbone Module\n")
    network_backbone_module <- network_backbone_server(
      "network_backbone_module",
      db_connection = db_pool
    )
  } else {
    cat("⚠️ Network Backbone Module not available\n")
  }

  # Initialize Amendment Pattern Analysis Module (Sprint 2 - Network Analytics)
  if (exists("amendmentServer")) {
    cat("✅ Initializing Amendment Pattern Analysis Module\n")
    amendment_module <- amendmentServer(
      "amendment_module",
      db_connection = db_pool,
      db_available = DB_AVAILABLE,
      documents_table = DOCUMENTS_TABLE
    )
  } else {
    cat("⚠️ Amendment Pattern Analysis Module not available\n")
  }

  # Initialize Anomaly Detection Module (Sprint 2 - Network Analytics)
  if (exists("anomalyServer")) {
    cat("✅ Initializing Anomaly Detection Module\n")
    anomaly_module <- anomalyServer(
      "anomaly_module",
      db_connection = db_pool,
      db_available = DB_AVAILABLE,
      documents_table = DOCUMENTS_TABLE
    )
  } else {
    cat("⚠️ Anomaly Detection Module not available\n")
  }

  # Initialize Semantic Search Module (Sprint 3 - Advanced NLP)
  if (exists("semantic_search_server")) {
    cat("✅ Initializing Semantic Search Module\n")
    semantic_search <- semantic_search_server(
      "semantic_search_module",
      db_pool = db_pool
    )
  } else {
    cat("⚠️ Semantic Search Module not available\n")
  }

  # Initialize Topic Explorer Module (Sprint 3 - Advanced NLP)
  if (exists("topic_explorer_server")) {
    cat("✅ Initializing Topic Explorer Module\n")
    topic_explorer <- topic_explorer_server(
      "topic_explorer_module",
      db_pool = db_pool
    )
  } else {
    cat("⚠️ Topic Explorer Module not available\n")
  }

  # Initialize BERT Precedent Search Module (Sprint 3 - Advanced NLP)
  if (exists("bert_precedent_server")) {
    cat("✅ Initializing BERT Precedent Search Module\n")
    bert_precedent <- bert_precedent_server(
      "bert_precedent_module",
      db_pool = db_pool
    )
  } else {
    cat("⚠️ BERT Precedent Search Module not available\n")
  }

  # Initialize Survival Analysis Module (Sprint 4 - PRD 4.1)
  if (exists("survival_server")) {
    cat("✅ Initializing Survival Analysis Module\n")
    survival_analysis <- survival_server(
      "survival_module",
      pool = secure_db_connection
    )
  } else {
    cat("⚠️ Survival Analysis Module not available\n")
  }

  # Initialize Voting Prediction Module (Sprint 4 - PRD 4.2)
  if (exists("voting_server")) {
    cat("✅ Initializing Voting Prediction Module\n")
    voting_prediction <- voting_server(
      "voting_module",
      pool = secure_db_connection
    )
  } else {
    cat("⚠️ Voting Prediction Module not available\n")
  }

  # Initialize Library Analytics Dashboard Module (Sprint 4 - Phase 2)
  if (exists("library_analytics_server")) {
    cat("✅ Initializing Library Analytics Dashboard Module\n")
    library_analytics <- library_analytics_server(
      input = input,
      output = output,
      session = session
    )
  } else {
    cat("⚠️ Library Analytics Dashboard Module not available\n")
  }

  # Initialize Methodology Module
  if (exists("methodology_server")) {
    cat("✅ Initializing Methodology Module\n")
    methodology_server("methodology_module")
  } else {
    cat("⚠️ Methodology Module not available\n")
  }

  # Initialize Executive Summary Module (Sprint 4 - Phase 2)
  # Module now navbarPage-compatible with panel_box layout
  if (exists("executive_summary_server")) {
    cat("✅ Initializing Executive Summary Module\n")
    moduleServer("executive_summary_module", executive_summary_server)
  } else {
    cat("⚠️ Executive Summary Module not available\n")
  }

  # Initialize Executive Export Module (Week 2 - BI Enhancements)
  if (exists("executive_export_server") && DB_AVAILABLE) {
    tryCatch({
      cat("✅ Initializing Executive Export Module\n")
      executive_export_server("executive_export_module", db_pool = pool)
    }, error = function(e) {
      cat("⚠️ Executive Export Module initialization failed:", e$message, "\n")
      cat("⚠️ Export features will be disabled\n")
    })
  } else {
    cat("⚠️ Executive Export Module not available or DB not connected\n")
  }

  # -- ESTADO MAPEADO MAP MODULE --
  if (exists("estadoMapeadoServer") && DB_AVAILABLE) {
    cat("✅ Initializing Estado Mapeado Map Module\n")
    tryCatch({
      estadoMapeadoServer(
        "estado_mapeado_map",
        db_connection = db_pool,
        table_name = DOCUMENTS_TABLE
      )
    }, error = function(e) {
      cat("❌ Error initializing Estado Mapeado Module:", e$message, "\n")
    })
  } else {
    if (!exists("estadoMapeadoServer")) {
      cat("⚠️ Estado Mapeado Module not available\n")
    }
    if (!DB_AVAILABLE) {
      cat("⚠️ Database not available - Estado Mapeado Module disabled\n")
    }
  }

  # -- BASIC LIBRARY SERVER FALLBACK --
  if (!exists("libraryEnhancedServer")) {

    # FALLBACK: Basic library implementation
    # 1. A reactiveValues object to hold the current filter state.
    filters <- reactiveValues(
      search = "",
      tipo = "Todos",
      mostrar = 100,
      trigger = 0
    )

    # Fire a single trigger once the UI is fully bound
    session$onFlushed(function() {
      isolate({
        filters$trigger <- filters$trigger + 1
      })
    }, once = TRUE)

    # 2. Observer for the 'Apply' button.
    observeEvent(input$library_apply, {
      cat("=== APPLY BUTTON CLICKED ===\n")
      filters$search <- input$library_search
      filters$tipo <- input$library_tipo
      filters$mostrar <- as.numeric(input$library_mostrar)
      filters$trigger <- filters$trigger + 1
    })

    # 3. Observer for the 'Clear' button.
    observeEvent(input$library_clear, {
      cat("=== CLEAR BUTTON CLICKED ===\n")
      updateTextInput(session, "library_search", value = "")
      updateSelectInput(session, "library_tipo", selected = "Todos")
      updateSelectInput(session, "library_mostrar", selected = 100)

      filters$search <- ""
      filters$tipo <- "Todos"
      filters$mostrar <- 100
      filters$trigger <- filters$trigger + 1
    })

    # 4. A reactive expression to fetch data from the database.
    library_data <- reactive({
      if (!DB_AVAILABLE) {
        return(data.frame(
          Message = c("Database connection not available",
                     "To configure the database:",
                     "1. Set environment variables: PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD",
                     "2. Or run: source('setup_local_env.R')",
                     "3. Then restart the application")
        ))
      }

      current_search <- filters$search
      current_tipo <- filters$tipo
      current_mostrar <- as.numeric(filters$mostrar)
      current_trigger <- filters$trigger

      # Validate search input (Phase 1: Security Integration - Input Validation)
      if (current_search != "") {
        validation_result <- validate_search_term(current_search)
        if (!validation_result$valid) {
          return(data.frame(
            Error = paste("Erro de validação:", validation_result$error)
          ))
        }
        # Use sanitized version
        current_search <- validation_result$sanitized
      }

      # Build parameterized query (Phase 1: Security Integration - SQL Injection Prevention)
      query <- paste("SELECT id, titulo, tipo, data FROM", DOCUMENTS_TABLE)
      conditions <- list()
      params <- list()
      param_index <- 1

      # Add search condition with parameterization
      if (current_search != "") {
        conditions <- c(conditions, paste0("titulo ILIKE $", param_index))
        params[[param_index]] <- paste0("%", current_search, "%")
        param_index <- param_index + 1
      }

      # Add tipo filter with parameterization
      if (current_tipo != "Todos") {
        conditions <- c(conditions, paste0("tipo = $", param_index))
        params[[param_index]] <- current_tipo
        param_index <- param_index + 1
      }

      # Build WHERE clause
      if (length(conditions) > 0) {
        query <- paste(query, "WHERE", paste(conditions, collapse = " AND "))
      }

      # Add LIMIT with parameterization
      query <- paste(query, "ORDER BY data DESC LIMIT $", param_index)
      params[[param_index]] <- as.integer(current_mostrar)

      cat("Executing parameterized query with", length(params), "parameters\n")

      tryCatch({
        result <- cached_query(
          connection = db_pool,
          query = query,
          params = params,
          ttl = CACHE_TTL$search,
          cache_type = "library"
        )
        cat("Query returned", nrow(result), "rows\n")
        if (nrow(result) == 0) {
          return(data.frame(Message = "Nenhum documento encontrado para os filtros selecionados."))
        }
        result
      }, error = function(e) {
        data.frame(Error = e$message)
      })
    })

    # 5. Render the table
    output$library_table <- DT::renderDataTable({
      cat("=== LIBRARY_TABLE OUTPUT RENDERING ===\n")
      library_data()
    }, options = list(pageLength = 10, scrollX = TRUE))

    outputOptions(output, "library_table", suspendWhenHidden = FALSE)
  }

  # -- HOME TAB SERVER LOGIC (EXECUTIVE SUMMARY) --

  # Cached reactive for Home tab statistics
  # This executes all basic stats queries once and caches the results
  # Only re-executes when database connection changes or on manual invalidation
  home_stats <- reactive({
    if (!DB_AVAILABLE) {
      return(list(
        total_docs = NA,
        doc_types_count = NA,
        latest_date = NA,
        oldest_date = NA,
        error = FALSE
      ))
    }

    tryCatch({
      # Execute all basic stats with caching (Phase 2, Task 2.2)
      total_result <- cached_query(
        connection = db_pool,
        query = paste("SELECT COUNT(*) as total FROM", DOCUMENTS_TABLE),
        ttl = CACHE_TTL$dashboard,
        cache_type = "dashboard"
      )
      types_result <- cached_query(
        connection = db_pool,
        query = paste("SELECT COUNT(DISTINCT tipo) as count FROM", DOCUMENTS_TABLE),
        ttl = CACHE_TTL$dashboard,
        cache_type = "dashboard"
      )
      latest_result <- cached_query(
        connection = db_pool,
        query = paste("SELECT MAX(data) as latest FROM", DOCUMENTS_TABLE),
        ttl = CACHE_TTL$dashboard,
        cache_type = "dashboard"
      )
      oldest_result <- cached_query(
        connection = db_pool,
        query = paste("SELECT MIN(data) as oldest FROM", DOCUMENTS_TABLE),
        ttl = CACHE_TTL$dashboard,
        cache_type = "dashboard"
      )

      list(
        total_docs = total_result$total,
        doc_types_count = types_result$count,
        latest_date = latest_result$latest,
        oldest_date = oldest_result$oldest,
        error = FALSE
      )
    }, error = function(e) {
      cat("Error fetching home stats:", e$message, "\n")
      list(
        total_docs = NA,
        doc_types_count = NA,
        latest_date = NA,
        oldest_date = NA,
        error = TRUE
      )
    })
  })

  # Total documents count - uses cached data
  output$home_total_docs <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.na(stats$total_docs)) return("N/A")
    format(stats$total_docs, big.mark = ",")
  })

  # Number of distinct document types - uses cached data
  output$home_doc_types_count <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.na(stats$doc_types_count)) return("N/A")
    as.character(stats$doc_types_count)
  })

  # Latest document date - uses cached data
  output$home_latest_date <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.null(stats$latest_date) || is.na(stats$latest_date)) return("N/A")
    format(as.Date(stats$latest_date), "%d/%m/%Y")
  })

  # Oldest document date - uses cached data
  output$home_oldest_date <- renderText({
    stats <- home_stats()
    if (stats$error) return("Error")
    if (is.null(stats$oldest_date) || is.na(stats$oldest_date)) return("N/A")
    format(as.Date(stats$oldest_date), "%d/%m/%Y")
  })

  # Cached reactive for Home tab type breakdown
  home_type_breakdown_data <- reactive({
    if (!DB_AVAILABLE) {
      return(data.frame(Message = "Database not available"))
    }

    tryCatch({
      query <- paste0(
        "SELECT tipo AS \"Document Type\", ",
        "COUNT(*) as \"Count\", ",
        "ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM ", DOCUMENTS_TABLE, "), 2) as \"Percentage\" ",
        "FROM ", DOCUMENTS_TABLE, " ",
        "GROUP BY tipo ",
        "ORDER BY COUNT(*) DESC"
      )
      pool::dbGetQuery(db_pool, query)
    }, error = function(e) {
      cat("Error fetching type breakdown:", e$message, "\n")
      data.frame(Error = e$message)
    })
  })

  # Document type breakdown table - uses cached data
  output$home_type_breakdown <- DT::renderDataTable({
    home_type_breakdown_data()
  }, options = list(pageLength = 10, scrollX = TRUE, dom = 't'))

  # Cached reactive for Home tab recent activity
  home_recent_activity_data <- reactive({
    if (!DB_AVAILABLE) {
      return(data.frame(Message = "Database not available"))
    }

    tryCatch({
      query <- paste0(
        "SELECT tipo AS \"Type\", ",
        "data AS \"Date\", ",
        "LEFT(titulo, 50) || '...' AS \"Title\" ",
        "FROM ", DOCUMENTS_TABLE, " ",
        "ORDER BY data DESC ",
        "LIMIT 10"
      )
      result <- pool::dbGetQuery(db_pool, query)

      # Format the date column
      if (nrow(result) > 0 && "Date" %in% names(result)) {
        result$Date <- format(as.Date(result$Date), "%d/%m/%Y")
      }

      result
    }, error = function(e) {
      cat("Error fetching recent activity:", e$message, "\n")
      data.frame(Error = e$message)
    })
  })

  # Recent activity table - uses cached data
  output$home_recent_activity <- DT::renderDataTable({
    home_recent_activity_data()
  }, options = list(pageLength = 10, scrollX = TRUE, dom = 't'))

  # ===========================================================================
  # -- ENHANCED GEOGRAPHIC SERVER LOGIC --
  # ===========================================================================

  # Reactive values for Geographic filters and settings
  geo_filters <- reactiveValues(
    tipo = "Todos",
    date_start = NULL,
    date_end = NULL,
    viz_mode = "absolute",
    viz_level = "state",
    trigger = 1
  )

  # Store current map data and statistics for export
  current_map_data <- reactiveVal(NULL)
  current_viz_stats <- reactiveVal(NULL)

  # Apply button observer - captures all filter and visualization settings
  observeEvent(input$geo_apply, {
    geo_filters$tipo <- input$geo_filter_tipo
    geo_filters$date_start <- input$geo_date_range[1]
    geo_filters$date_end <- input$geo_date_range[2]
    geo_filters$viz_mode <- input$geo_viz_mode
    geo_filters$viz_level <- input$geo_viz_level
    geo_filters$trigger <- geo_filters$trigger + 1

    showNotification("Atualizando visualização...", type = "message", duration = 2)
  })

  # Clear button observer
  observeEvent(input$geo_clear, {
    updateSelectInput(session, "geo_filter_tipo", selected = "Todos")
    updateDateRangeInput(session, "geo_date_range", start = NULL, end = NULL)
    updateSelectInput(session, "geo_viz_mode", selected = "absolute")
    updateSelectInput(session, "geo_viz_level", selected = "state")

    geo_filters$tipo <- "Todos"
    geo_filters$date_start <- NULL
    geo_filters$date_end <- NULL
    geo_filters$viz_mode <- "absolute"
    geo_filters$viz_level <- "state"
    geo_filters$trigger <- geo_filters$trigger + 1

    showNotification("Filtros limpos", type = "message", duration = 2)
  })

  # Auto-update when visualization settings change
  observeEvent(input$geo_viz_mode, {
    if (geo_filters$trigger > 1) {  # Skip initial load
      geo_filters$viz_mode <- input$geo_viz_mode
      geo_filters$trigger <- geo_filters$trigger + 1
    }
  }, ignoreInit = TRUE)

  observeEvent(input$geo_viz_level, {
    if (geo_filters$trigger > 1) {  # Skip initial load
      geo_filters$viz_level <- input$geo_viz_level
      geo_filters$trigger <- geo_filters$trigger + 1
    }
  }, ignoreInit = TRUE)

  # ===========================================================================
  # -- ENHANCED EXPORT HANDLERS --
  # ===========================================================================

  # CSV export handler
  output$geo_download_csv <- downloadHandler(
    filename = function() {
      paste0("geographic_data_", geo_filters$viz_level, "_", format(Sys.Date(), "%Y%m%d"), ".csv")
    },
    content = function(file) {
      data <- current_map_data()
      result <- export_geographic_data(data, format = "CSV", filename = basename(file))

      if (result$success && file.exists(result$file_path)) {
        file.copy(result$file_path, file, overwrite = TRUE)
      } else {
        write.csv(data.frame(Error = result$error %||% "Export failed"), file, row.names = FALSE)
      }
    }
  )

  # GeoJSON export handler
  output$geo_download_geojson <- downloadHandler(
    filename = function() {
      paste0("geographic_data_", geo_filters$viz_level, "_", format(Sys.Date(), "%Y%m%d"), ".geojson")
    },
    content = function(file) {
      data <- current_map_data()
      result <- export_geographic_data(data, format = "GeoJSON", filename = basename(file))

      if (result$success && file.exists(result$file_path)) {
        file.copy(result$file_path, file, overwrite = TRUE)
      } else {
        writeLines(paste("Error:", result$error %||% "No geographic data available"), file)
      }
    }
  )

  # PNG map export handler
  output$geo_download_png <- downloadHandler(
    filename = function() {
      paste0("geographic_map_", format(Sys.Date(), "%Y%m%d"), ".png")
    },
    content = function(file) {
      map_data <- current_map_data()

      if (is.null(map_data) || nrow(map_data) == 0) {
        p <- ggplot() +
          annotate("text", x = 0, y = 0,
                   label = "No data available\nApply filters first",
                   size = 6) +
          theme_void()
        ggsave(file, plot = p, width = 10, height = 8, dpi = 300, bg = "white")
        return()
      }

      tryCatch({
        if (!inherits(map_data, "sf")) {
          map_data <- sf::st_as_sf(map_data)
        }

        value_col <- switch(geo_filters$viz_mode,
          "absolute" = "document_count",
          "per_capita" = "docs_per_capita",
          "density" = "docs_per_km2",
          "temporal" = "recent_docs_pct",
          "document_count"
        )

        if (!value_col %in% names(map_data)) {
          value_col <- "document_count"
        }

        values <- map_data[[value_col]]
        values <- values[!is.na(values) & is.finite(values)]
        max_val <- max(values, na.rm = TRUE)

        p <- ggplot(data = map_data) +
          geom_sf(aes(fill = get(value_col)), color = "#444444", size = 0.3) +
          scale_fill_gradient(
            low = "#fff5eb",
            high = "#d62728",
            name = switch(geo_filters$viz_mode,
              "absolute" = "Documents",
              "per_capita" = "Docs/100k",
              "density" = "Docs/km²",
              "temporal" = "Recent %",
              "Documents"
            ),
            breaks = if(max_val > 0) pretty(c(0, max_val), n = 5) else c(0, 1),
            limits = c(0, max(max_val, 1))
          ) +
          labs(
            title = "Geographic Distribution of Legislative Documents",
            subtitle = paste("Data updated:", format(DATA_EXTRACTION_DATE, "%d/%m/%Y")),
            caption = "Source: Monitor Legislativo"
          ) +
          theme_minimal(base_size = 12) +
          theme(
            plot.title = element_text(face = "bold", size = 16, hjust = 0.5),
            plot.subtitle = element_text(size = 12, hjust = 0.5, color = "gray40"),
            plot.caption = element_text(size = 10, hjust = 1, color = "gray50"),
            legend.position = "right",
            legend.title = element_text(face = "bold"),
            panel.grid = element_blank(),
            axis.text = element_blank(),
            axis.title = element_blank()
          )

        ggsave(file, plot = p, width = 12, height = 10, dpi = 300, bg = "white")

      }, error = function(e) {
        p <- ggplot() +
          annotate("text", x = 0, y = 0,
                   label = paste("Export error:", e$message),
                   size = 6, color = "red") +
          theme_void()
        ggsave(file, plot = p, width = 10, height = 8, dpi = 300, bg = "white")
      })
    }
  )

  # SVG export handler
  output$geo_download_svg <- downloadHandler(
    filename = function() {
      paste0("geographic_map_", format(Sys.Date(), "%Y%m%d"), ".svg")
    },
    content = function(file) {
      tryCatch({
        data <- enhanced_geo_data()

        if (is.null(data) || nrow(data) == 0) {
          showNotification("No data available for export", type = "warning", duration = 3)
          return()
        }

        # Get current visualization mode
        current_mode <- geo_filters$viz_mode
        if (is.null(current_mode)) current_mode <- "absolute"

        # Create static plot
        plot <- create_static_map_plot(data, mode = current_mode)

        # Save as SVG
        ggsave(
          file,
          plot = plot,
          device = "svg",
          width = 12,
          height = 10,
          units = "in",
          dpi = 300
        )

        showNotification("SVG exported successfully!", type = "message", duration = 3)

      }, error = function(e) {
        cat("SVG export error:", e$message, "\n")
        showNotification(paste("SVG export failed:", e$message), type = "error", duration = 5)

        # Create error plot
        p <- ggplot() +
          annotate("text", x = 0, y = 0,
                   label = paste("Export error:", e$message),
                   size = 6, color = "red") +
          theme_void()
        ggsave(file, plot = p, device = "svg", width = 10, height = 8, bg = "white")
      })
    }
  )

  # PDF export handler
  output$geo_download_pdf <- downloadHandler(
    filename = function() {
      paste0("geographic_map_", format(Sys.Date(), "%Y%m%d"), ".pdf")
    },
    content = function(file) {
      tryCatch({
        data <- enhanced_geo_data()

        if (is.null(data) || nrow(data) == 0) {
          showNotification("No data available for export", type = "warning", duration = 3)
          return()
        }

        # Get current visualization mode
        current_mode <- geo_filters$viz_mode
        if (is.null(current_mode)) current_mode <- "absolute"

        # Create static plot
        plot <- create_static_map_plot(data, mode = current_mode)

        # Save as PDF
        ggsave(
          file,
          plot = plot,
          device = "pdf",
          width = 12,
          height = 10,
          units = "in",
          dpi = 300
        )

        showNotification("PDF exported successfully!", type = "message", duration = 3)

      }, error = function(e) {
        cat("PDF export error:", e$message, "\n")
        showNotification(paste("PDF export failed:", e$message), type = "error", duration = 5)

        # Create error plot
        p <- ggplot() +
          annotate("text", x = 0, y = 0,
                   label = paste("Export error:", e$message),
                   size = 6, color = "red") +
          theme_void()
        ggsave(file, plot = p, device = "pdf", width = 10, height = 8, bg = "white")
      })
    }
  )

  # ===========================================================================
  # -- ENHANCED MAP RENDERING LOGIC --
  # ===========================================================================

  # Reactive expression for loading and processing geographic data
  enhanced_geo_data <- reactive({
    # Establish dependencies
    current_trigger <- geo_filters$trigger
    current_tipo <- geo_filters$tipo
    current_date_start <- geo_filters$date_start
    current_date_end <- geo_filters$date_end
    current_mode <- geo_filters$viz_mode
    current_level <- geo_filters$viz_level

    cat("\n=== LOADING ENHANCED GEOGRAPHIC DATA ===\n")
    cat("Level:", current_level, "| Mode:", current_mode, "| Filter:", current_tipo, "\n")

    if (!DB_AVAILABLE) {
      cat("⚠️ Database not available\n")
      return(NULL)
    }

    # Build filters list
    filters <- list()
    if (current_tipo != "Todos") {
      filters$tipo <- current_tipo
    }
    if (!is.null(current_date_start) && !is.null(current_date_end)) {
      filters$date_start <- current_date_start
      filters$date_end <- current_date_end
    }

    # Load data using enhanced module
    tryCatch({
      data <- load_enhanced_geographic_data(
        db_conn = secure_db_connection,
        level = current_level,
        filters = filters,
        include_geometry = TRUE
      )

      if (!is.null(data) && nrow(data) > 0) {
        cat("✅ Loaded", nrow(data), "geographic features\n")

        # Calculate and store statistics
        stats <- calculate_viz_statistics(data)
        current_viz_stats(stats)

        # Store data for export
        current_map_data(data)

        return(data)
      } else {
        cat("⚠️ No geographic data returned\n")
        return(NULL)
      }

    }, error = function(e) {
      cat("❌ Error loading geographic data:", e$message, "\n")
      return(NULL)
    })
  })

  # Render enhanced choropleth map using leaflet
  output$geo_map <- leaflet::renderLeaflet({
    cat("=== RENDERING ENHANCED GEOGRAPHIC MAP ===\n")

    # Get enhanced data
    data <- enhanced_geo_data()

    if (is.null(data)) {
      cat("⚠️ No data available - creating empty map\n")
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -54, lat = -15, zoom = 4) %>%
        addMarkers(lng = -54, lat = -15,
                  popup = "No data available. Please check database connection and apply filters."))
    }

    # Get current visualization settings
    current_mode <- geo_filters$viz_mode
    current_level <- geo_filters$viz_level

    # Build filters for context
    filters <- list()
    if (geo_filters$tipo != "Todos") {
      filters$tipo <- geo_filters$tipo
    }

    # Create enhanced choropleth map
    tryCatch({
      map <- create_enhanced_choropleth(
        data = data,
        mode = current_mode,
        level = current_level,
        filters = filters
      )

      cat("✅ Enhanced map rendered successfully\n")
      return(map)

    }, error = function(e) {
      cat("❌ Error rendering map:", e$message, "\n")
      # Return basic map on error
      return(leaflet() %>%
        addTiles() %>%
        setView(lng = -54, lat = -15, zoom = 4) %>%
        addMarkers(lng = -54, lat = -15,
                  popup = paste("Error rendering map:", e$message)))
    })
  })

  # Statistics outputs
  output$geo_stat_features <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats)) return("--")
    format(stats$total_features, big.mark = ",")
  })

  output$geo_stat_documents <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats)) return("--")
    format(as.integer(stats$total_documents), big.mark = ",", scientific = FALSE)
  })

  output$geo_stat_avg <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats)) return("--")
    format(round(as.numeric(stats$avg_documents), 1), big.mark = ",", scientific = FALSE)
  })

  output$geo_stat_range <- renderText({
    stats <- current_viz_stats()
    if (is.null(stats) || is.null(stats$date_range)) return("--")
    stats$date_range
  })

  # Geographic coverage outputs
  output$geo_coverage_mapped <- renderText({
    if (!DB_AVAILABLE) return("--")
    # Get state documents (excluding Federal and Justiça Trabalho)
    tryCatch({
      result <- pool::dbGetQuery(db_pool,
        "SELECT COUNT(*) as count FROM documents WHERE estado IS NOT NULL AND estado != '' AND estado NOT IN ('Federal', 'Justiça Trabalho')")
      format(result$count[1], big.mark = ",")
    }, error = function(e) "--")
  })

  output$geo_coverage_federal <- renderText({
    if (!DB_AVAILABLE) return("--")
    tryCatch({
      result <- pool::dbGetQuery(db_pool,
        "SELECT COUNT(*) as count FROM documents WHERE estado = 'Federal'")
      format(result$count[1], big.mark = ",")
    }, error = function(e) "--")
  })

  output$geo_coverage_labor <- renderText({
    if (!DB_AVAILABLE) return("--")
    tryCatch({
      result <- pool::dbGetQuery(db_pool,
        "SELECT COUNT(*) as count FROM documents WHERE estado = 'Justiça Trabalho'")
      format(result$count[1], big.mark = ",")
    }, error = function(e) "--")
  })

  output$geo_coverage_no_urn <- renderText({
    if (!DB_AVAILABLE) return("--")
    tryCatch({
      result <- pool::dbGetQuery(db_pool,
        "SELECT COUNT(*) as count FROM documents WHERE estado IS NULL OR estado = ''")
      format(result$count[1], big.mark = ",")
    }, error = function(e) "--")
  })

  # === FEDERAL LEGISLATION OUTPUTS ===

  # Total count of federal documents
  output$federal_total_count <- renderText({
    if (!DB_AVAILABLE) return("--")
    tryCatch({
      result <- pool::dbGetQuery(db_pool,
        "SELECT COUNT(*) as count FROM documents WHERE estado = 'Federal'")
      format(result$count[1], big.mark = ".", decimal.mark = ",")
    }, error = function(e) "--")
  })

  # Timeline chart - federal documents over years
  output$federal_timeline <- renderPlot({
    if (!DB_AVAILABLE) {
      plot.new()
      text(0.5, 0.5, "Banco de dados não disponível", cex = 1.2, col = "gray")
      return()
    }

    tryCatch({
      # Query federal documents by year
      timeline_data <- pool::dbGetQuery(db_pool,
        "SELECT
          EXTRACT(YEAR FROM data::date) as year,
          COUNT(*) as count
        FROM documents
        WHERE estado = 'Federal'
          AND data IS NOT NULL
          AND data != ''
          AND EXTRACT(YEAR FROM data::date) >= 2000
        GROUP BY year
        ORDER BY year")

      if (nrow(timeline_data) == 0) {
        plot.new()
        text(0.5, 0.5, "Sem dados disponíveis", cex = 1.2, col = "gray")
        return()
      }

      # Create timeline plot
      par(mar = c(4, 4, 2, 1), family = "sans")
      plot(timeline_data$year, timeline_data$count,
           type = "l", lwd = 3, col = "#ea580c",
           xlab = "Ano", ylab = "Número de Documentos",
           main = "",
           las = 1, cex.axis = 0.9, cex.lab = 1.0)

      # Add points
      points(timeline_data$year, timeline_data$count,
             pch = 19, col = "#ea580c", cex = 1.2)

      # Add grid
      grid(col = "gray90", lty = 1)

      # Add trend line
      if (nrow(timeline_data) > 2) {
        trend_model <- lm(count ~ year, data = timeline_data)
        lines(timeline_data$year, predict(trend_model),
              col = "#dc2626", lty = 2, lwd = 2)
      }

    }, error = function(e) {
      plot.new()
      text(0.5, 0.5, paste("Erro:", e$message), cex = 1, col = "red")
    })
  })

  # Type breakdown chart
  output$federal_type_breakdown <- renderPlot({
    if (!DB_AVAILABLE) {
      plot.new()
      text(0.5, 0.5, "Banco de dados não disponível", cex = 1.2, col = "gray")
      return()
    }

    tryCatch({
      # Query federal documents by type (extracted from URN)
      type_data <- pool::dbGetQuery(db_pool,
        "SELECT
          CASE
            WHEN SUBSTRING(urn FROM 'br:[^:]+:([^:]+):') IS NULL OR SUBSTRING(urn FROM 'br:[^:]+:([^:]+):') = ''
            THEN 'Não especificado'
            ELSE REPLACE(SUBSTRING(urn FROM 'br:[^:]+:([^:]+):'), '.', ' ')
          END as tipo,
          COUNT(*) as count
        FROM documents
        WHERE estado = 'Federal'
        GROUP BY CASE
            WHEN SUBSTRING(urn FROM 'br:[^:]+:([^:]+):') IS NULL OR SUBSTRING(urn FROM 'br:[^:]+:([^:]+):') = ''
            THEN 'Não especificado'
            ELSE REPLACE(SUBSTRING(urn FROM 'br:[^:]+:([^:]+):'), '.', ' ')
          END
        ORDER BY count DESC
        LIMIT 8")

      if (nrow(type_data) == 0) {
        plot.new()
        text(0.5, 0.5, "Sem dados disponíveis", cex = 1.2, col = "gray")
        return()
      }

      # Convert count to numeric and create named vector
      counts <- as.numeric(type_data$count)
      names(counts) <- type_data$tipo

      # Create horizontal bar chart
      par(mar = c(4, 8, 2, 2), family = "sans")
      barplot(counts,
              horiz = TRUE,
              las = 1,
              col = colorRampPalette(c("#fed7aa", "#ea580c"))(length(counts)),
              border = NA,
              xlab = "Número de Documentos",
              cex.names = 0.85,
              cex.axis = 0.9)

      # Add grid
      grid(col = "gray90", lty = 1, nx = NULL, ny = NA)

    }, error = function(e) {
      plot.new()
      text(0.5, 0.5, paste("Erro:", e$message), cex = 1, col = "red")
    })
  })

  # Loading indicator
  output$geo_loading_indicator <- renderUI({
    data <- enhanced_geo_data()
    if (is.null(data)) {
      div(
        style = "position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 1000; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
        icon("spinner", class = "fa-spin fa-3x"),
        h4("Carregando dados geográficos...", style = "margin-top: 10px;")
      )
    } else {
      NULL
    }
  })

  # Force Geographic map to bind to reactive graph even when tab is hidden
  outputOptions(output, "geo_map", suspendWhenHidden = FALSE)

  # -- TRANSPORT CORRIDORS SERVER LOGIC --

  # Reactive data for transport corridors (filtered legislative documents)
  transport_legislative_data <- reactive({
    if (!DB_AVAILABLE) return(NULL)

    tryCatch({
      # Get basic document data
      query <- paste0("
        SELECT
          id,
          titulo,
          tipo,
          data,
          estado,
          municipio,
          texto,
          url
        FROM ", DOCUMENTS_TABLE, "
        WHERE texto IS NOT NULL
        LIMIT 10000
      ")

      docs <- pool::dbGetQuery(db_pool, query)

      # Rename columns to match transport module expectations
      if (nrow(docs) > 0) {
        docs$title <- docs$titulo
        docs$type <- docs$tipo
        docs$date <- as.Date(docs$data)
        docs$state <- docs$estado

        cat("📊 Loaded", nrow(docs), "documents for transport corridor analysis\n")
      }

      return(docs)

    }, error = function(e) {
      cat("❌ Error loading transport data:", e$message, "\n")
      return(NULL)
    })
  })

  # Call transport corridor server module if available
  if (!is.null(transport_module)) {
    transport_corridor_values <- transport_module$server(
      "transport_corridor",
      legislative_data = transport_legislative_data
    )
    cat("✅ Transport Corridor server module initialized\n")
  } else {
    cat("⚠️ Transport Corridor server module not available\n")
  }

  # -- ANALYTICS SERVER LOGIC --

  analytics_data <- reactive({
    if (!DB_AVAILABLE) return(NULL)

    tryCatch({
      list(
        by_type = pool::dbGetQuery(db_pool,
          paste("SELECT tipo_documento AS type, COUNT(*) AS n FROM", DOCUMENTS_TABLE,
                "WHERE tipo_documento IS NOT NULL GROUP BY tipo_documento ORDER BY n DESC")),
        by_month = pool::dbGetQuery(db_pool,
          paste0("SELECT TO_DATE(ano || '-' || mes || '-01', 'YYYY-MM-DD') AS month, COUNT(*) AS n ",
                 "FROM ", DOCUMENTS_TABLE, " ",
                 "WHERE ano IS NOT NULL AND mes IS NOT NULL ",
                 "GROUP BY ano, mes ",
                 "ORDER BY ano, mes"))
      )
    }, error = function(e) {
      cat("Analytics query error:", e$message, "\n")
      return(NULL)
    })
  })

  output$analytics_type_bar <- renderPlot({
    dat <- analytics_data()
    if (is.null(dat)) return()
    ggplot(dat$by_type, aes(x = reorder(type, n), y = n)) +
      geom_col(fill = "steelblue") +
      coord_flip() +
      labs(x = "Tipo", y = "Quantidade de Documentos", title = "Documentos por Tipo") +
      theme_minimal()
  })

  output$analytics_month_line <- renderPlot({
    dat <- analytics_data()
    if (is.null(dat)) return()
    ggplot(dat$by_month, aes(x = as.Date(month), y = n)) +
      geom_line(color = "firebrick", size = 1) +
      geom_point(color = "firebrick") +
      labs(x = "Mês", y = "Quantidade", title = "Documentos por Mês") +
      theme_minimal()
  })

  # -- ADVANCED VISUALIZATIONS SERVER LOGIC (Priority 6) --

  # Reactive data for advanced visualizations
  advanced_viz_data <- reactive({
    if (!DB_AVAILABLE || is.null(secure_db_connection)) {
      return(NULL)
    }

    tryCatch({
      # Get document data for advanced visualizations
      query <- paste0(
        "SELECT tipo, data, titulo, ementa, estado ",
        "FROM ", DOCUMENTS_TABLE, " ",
        "WHERE data IS NOT NULL ",
        "LIMIT 1000"  # Limit for performance
      )
      pool::dbGetQuery(db_pool, query)
    }, error = function(e) {
      cat("Error loading advanced viz data:", e$message, "\n")
      NULL
    })
  }) %>% bindEvent(input$refresh_viz, ignoreNULL = FALSE)

  # Network visualization
  output$advanced_network_viz <- renderUI({
    data <- advanced_viz_data()
    if (is.null(data) || nrow(data) == 0) {
      return(div(
        class = "alert alert-warning",
        icon("exclamation-triangle"),
        " Dados insuficientes para gerar rede de citações. ",
        "Necessário conectar ao banco de dados e ter dados disponíveis."
      ))
    }

    # Check if networkD3 is available
    if (!requireNamespace("networkD3", quietly = TRUE)) {
      return(div(
        class = "alert alert-warning",
        icon("exclamation-triangle"),
        " Pacote 'networkD3' não instalado. ",
        "Execute: install.packages('networkD3')"
      ))
    }

    # Create simple network based on document types
    tryCatch({
      nodes <- data.frame(
        name = unique(data$tipo),
        group = 1
      )

      # Create edges based on co-occurrence by date
      edges_list <- list()
      for (i in seq_len(min(nrow(data) - 1, 100))) {
        edges_list[[i]] <- data.frame(
          source = match(data$tipo[i], nodes$name) - 1,
          target = match(data$tipo[i + 1], nodes$name) - 1,
          value = 1
        )
      }
      edges <- do.call(rbind, edges_list)
      edges <- edges[edges$source != edges$target, ]

      network <- networkD3::forceNetwork(
        Links = edges,
        Nodes = nodes,
        Source = "source",
        Target = "target",
        Value = "value",
        NodeID = "name",
        Group = "group",
        opacity = 0.9,
        zoom = TRUE,
        fontSize = 14
      )

      network
    }, error = function(e) {
      div(
        class = "alert alert-danger",
        icon("times-circle"),
        " Erro ao gerar rede: ", e$message
      )
    })
  })

  # Treemap visualization
  output$advanced_treemap_viz <- renderPlotly({
    data <- advanced_viz_data()
    if (is.null(data) || nrow(data) == 0) {
      return(plotly::plot_ly() %>%
        plotly::layout(
          title = "Dados insuficientes",
          annotations = list(
            text = "Conecte ao banco de dados para visualizar",
            showarrow = FALSE
          )
        ))
    }

    # Create treemap of document types
    tryCatch({
      type_counts <- data %>%
        dplyr::group_by(tipo) %>%
        dplyr::summarise(count = n(), .groups = "drop") %>%
        dplyr::arrange(desc(count))

      plotly::plot_ly(
        type = "treemap",
        labels = type_counts$tipo,
        parents = rep("", nrow(type_counts)),
        values = type_counts$count,
        textposition = "middle center",
        marker = list(
          colorscale = "Viridis"
        )
      ) %>%
        plotly::layout(
          title = "Distribuição Hierárquica de Tipos de Documentos"
        )
    }, error = function(e) {
      plotly::plot_ly() %>%
        plotly::layout(
          title = paste("Erro:", e$message)
        )
    })
  })

  # Word cloud visualization
  output$advanced_wordcloud_viz <- renderUI({
    data <- advanced_viz_data()
    if (is.null(data) || nrow(data) == 0) {
      return(div(
        class = "alert alert-warning",
        icon("exclamation-triangle"),
        " Dados insuficientes para gerar nuvem de palavras."
      ))
    }

    # Check if wordcloud2 is available
    if (!requireNamespace("wordcloud2", quietly = TRUE)) {
      return(div(
        class = "alert alert-warning",
        icon("exclamation-triangle"),
        " Pacote 'wordcloud2' não instalado. ",
        "Execute: install.packages('wordcloud2')"
      ))
    }

    tryCatch({
      # Extract words from titles
      words <- tolower(unlist(strsplit(data$titulo, " ")))
      words <- words[nchar(words) > 3]  # Filter short words

      word_freq <- as.data.frame(table(words))
      colnames(word_freq) <- c("word", "freq")
      word_freq <- word_freq[order(-word_freq$freq), ]
      word_freq <- head(word_freq, input$wordcloud_max)

      wordcloud2::wordcloud2(
        data = word_freq,
        size = 0.5,
        color = "random-light",
        backgroundColor = "white"
      )
    }, error = function(e) {
      div(
        class = "alert alert-danger",
        icon("times-circle"),
        " Erro ao gerar nuvem de palavras: ", e$message
      )
    })
  })

  # Correlation visualization
  output$advanced_correlation_viz <- renderPlot({
    data <- advanced_viz_data()
    if (is.null(data) || nrow(data) == 0) {
      plot.new()
      text(0.5, 0.5, "Dados insuficientes para análise de correlação", cex = 1.5)
      return()
    }

    # Check if corrplot is available
    if (!requireNamespace("corrplot", quietly = TRUE)) {
      plot.new()
      text(0.5, 0.5, "Pacote 'corrplot' não instalado\nExecute: install.packages('corrplot')", cex = 1.2)
      return()
    }

    tryCatch({
      # Create correlation matrix from document types and states
      type_matrix <- table(data$tipo, data$estado)

      # If we have enough data, compute correlation
      if (nrow(type_matrix) > 1 && ncol(type_matrix) > 1) {
        cor_matrix <- cor(t(type_matrix))
        corrplot::corrplot(
          cor_matrix,
          method = "circle",
          type = "upper",
          tl.col = "black",
          tl.srt = 45,
          title = "Correlação entre Tipos de Documentos por Estado",
          mar = c(0, 0, 2, 0)
        )
      } else {
        plot.new()
        text(0.5, 0.5, "Dados insuficientes para matriz de correlação", cex = 1.5)
      }
    }, error = function(e) {
      plot.new()
      text(0.5, 0.5, paste("Erro:", e$message), cex = 1.2)
    })
  })

  # Note: Database connection is NOT closed per-session because it's a GLOBAL connection
  # shared across all users. Cloud Run will terminate the container when inactive,
  # which will automatically clean up the connection. Closing it on session end would
  # break the connection for other active users.
}

# ==============================================================================
# 5. RUN APPLICATION
# ==============================================================================
shinyApp(ui = ui, server = server)
