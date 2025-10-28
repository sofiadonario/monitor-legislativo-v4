# Executive Summary Tab UI
# Monitor Legislativo v4 - Executive Dashboard Interface
# ======================================================
# v61: Migrated from shinydashboard box() to bslib card()

# Wrap all UI elements in a single div() for bslib::nav_panel compatibility
div(
  # Strategic Insights Panel - Top Priority Information
  layout_columns(
    col_widths = 12,
    card(
      card_header("📊 Panorama da Legislação Brasileira"),
      class = "bg-primary text-white",
      layout_columns(
        col_widths = c(4, 4, 4),
        card(
          card_header("Áreas de Foco Atual"),
          uiOutput("exec_focus_areas")
        ),
        card(
          card_header("Atividade Legislativa"),
          uiOutput("exec_activity_summary")
        ),
        card(
          card_header("Qualidade da Cobertura"),
          uiOutput("exec_coverage_quality")
        )
      )
    )
  ),

  # Critical Metrics Dashboard - Enhanced Value Boxes - ALL NOW uiOutput
  layout_columns(
    col_widths = c(3, 3, 3, 3),
    uiOutput("exec_total_docs"),
    uiOutput("exec_states_coverage"),
    uiOutput("exec_recent_additions"),
    uiOutput("exec_data_freshness")
  ),

  # Key Performance Indicators - ALL NOW uiOutput
  layout_columns(
    col_widths = c(2, 2, 2, 2, 2, 2),
    uiOutput("exec_federal_docs"),
    uiOutput("exec_state_docs"),
    uiOutput("exec_municipal_docs"),
    uiOutput("exec_jurisprudence_docs"),
    uiOutput("exec_doctrine_docs"),
    uiOutput("exec_active_themes")
  ),

  # TEMPORARILY DISABLED - Testing crash fix
  # Trend Visualizations Row
  # layout_columns(
  #   col_widths = c(8, 4),
  #   # Document Publication Trends
  #   card(
  #     card_header("📈 Tendências de Publicação"),
  #     plotlyOutput("exec_publication_trends", height = "300px"),
  #     card_footer("Padrões mensais de publicação em todas as jurisdições")
  #   ),
  #   # Geographic Distribution
  #   card(
  #     card_header("🗺️ Distribuição Geográfica"),
  #     plotlyOutput("exec_geographic_dist", height = "300px"),
  #     card_footer("Distribuição de documentos por estado")
  #   )
  # ),
  #
  # # Legislative Themes and Recent Activity
  # layout_columns(
  #   col_widths = c(6, 6),
  #   # Top Legislative Themes
  #   card(
  #     card_header("🏛️ Principais Temas Legislativos"),
  #     DT::dataTableOutput("exec_top_themes"),
  #     card_footer("Temas mais frequentes em todos os documentos")
  #   ),
  #   # Recent High-Impact Documents
  #   card(
  #     card_header("📋 Documentos Recentes de Alto Impacto"),
  #     DT::dataTableOutput("exec_recent_docs"),
  #     card_footer("Últimos documentos legislativos importantes")
  #   )
  # ),

  # Data Quality and System Health
  layout_columns(
    col_widths = c(8, 4),
    # Data Quality Metrics
    card(
      card_header("✅ Avaliação da Qualidade dos Dados"),
      layout_columns(
        col_widths = c(3, 3, 3, 3),
        div(class = "quality-metric",
          h5("Completude", style = "margin: 0;"),
          div(class = "progress progress-sm",
            div(class = "progress-bar bg-success", style = "width: 94%", "94%")
          ),
          tags$small("Cobertura de metadados")
        ),
        div(class = "quality-metric",
          h5("Atualidade", style = "margin: 0;"),
          div(class = "progress progress-sm",
            div(class = "progress-bar bg-info", style = "width: 87%", "87%")
          ),
          tags$small("Score de atualização")
        ),
        div(class = "quality-metric",
          h5("Precisão", style = "margin: 0;"),
          div(class = "progress progress-sm",
            div(class = "progress-bar bg-warning", style = "width: 91%", "91%")
          ),
          tags$small("Taxa de validação")
        ),
        div(class = "quality-metric",
          h5("Consistência", style = "margin: 0;"),
          div(class = "progress progress-sm",
            div(class = "progress-bar bg-danger", style = "width: 83%", "83%")
          ),
          tags$small("Padrões de dados")
        )
      )
    ),
    # System Health - DISABLED (no server code)
    card(
      card_header("🔧 Status do Sistema"),
      # TEMPORARILY DISABLED - Testing crash fix (orphaned output)
      # uiOutput("exec_system_health"),
      div(
        style = "padding: 20px; text-align: center;",
        p("Status do sistema em desenvolvimento", style = "color: #7f8c8d;")
      ),
      card_footer("Monitoramento em tempo real")
    )
  )
)
