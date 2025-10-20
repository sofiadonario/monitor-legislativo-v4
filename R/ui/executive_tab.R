# Executive Summary Tab UI
# Monitor Legislativo v4 - Executive Dashboard Interface
# ======================================================

# Wrap all UI elements in tagList for proper sourcing
tagList(
  # Strategic Insights Panel - Top Priority Information
  fluidRow(
    box(
      title = "📊 Panorama da Legislação Brasileira",
      status = "primary",
      solidHeader = TRUE,
      width = 12,
      background = "light-blue",
      fluidRow(
        column(4,
          div(class = "insight-card",
            h4("Áreas de Foco Atual", style = "color: #2c3e50; margin-top: 0;"),
            uiOutput("exec_focus_areas"),
            style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;"
          )
        ),
        column(4,
          div(class = "insight-card",
            h4("Atividade Legislativa", style = "color: #2c3e50; margin-top: 0;"),
            uiOutput("exec_activity_summary"),
            style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;"
          )
        ),
        column(4,
          div(class = "insight-card",
            h4("Qualidade da Cobertura", style = "color: #2c3e50; margin-top: 0;"),
            uiOutput("exec_coverage_quality"),
            style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;"
          )
        )
      )
    )
  ),

  # Critical Metrics Dashboard - Enhanced Value Boxes - ALL NOW uiOutput
  fluidRow(
    column(3, uiOutput("exec_total_docs")),
    column(3, uiOutput("exec_states_coverage")),
    column(3, uiOutput("exec_recent_additions")),
    column(3, uiOutput("exec_data_freshness"))
  ),

  # Key Performance Indicators - ALL NOW uiOutput
  fluidRow(
    column(2, uiOutput("exec_federal_docs")),
    column(2, uiOutput("exec_state_docs")),
    column(2, uiOutput("exec_municipal_docs")),
    column(2, uiOutput("exec_jurisprudence_docs")),
    column(2, uiOutput("exec_doctrine_docs")),
    column(2, uiOutput("exec_active_themes"))
  ),

  # TEMPORARILY DISABLED - Testing crash fix
  # Trend Visualizations Row
  # fluidRow(
  #   # Document Publication Trends
  #   box(
  #     title = "📈 Tendências de Publicação",
  #     status = "info",
  #     solidHeader = TRUE,
  #     width = 8,
  #     plotlyOutput("exec_publication_trends", height = "300px"),
  #     footer = "Padrões mensais de publicação em todas as jurisdições"
  #   ),
  #   # Geographic Distribution
  #   box(
  #     title = "🗺️ Distribuição Geográfica",
  #     status = "success",
  #     solidHeader = TRUE,
  #     width = 4,
  #     plotlyOutput("exec_geographic_dist", height = "300px"),
  #     footer = "Distribuição de documentos por estado"
  #   )
  # ),
  #
  # # Legislative Themes and Recent Activity
  # fluidRow(
  #   # Top Legislative Themes
  #   box(
  #     title = "🏛️ Principais Temas Legislativos",
  #     status = "warning",
  #     solidHeader = TRUE,
  #     width = 6,
  #     DT::dataTableOutput("exec_top_themes"),
  #     footer = "Temas mais frequentes em todos os documentos"
  #   ),
  #   # Recent High-Impact Documents
  #   box(
  #     title = "📋 Documentos Recentes de Alto Impacto",
  #     status = "danger",
  #     solidHeader = TRUE,
  #     width = 6,
  #     DT::dataTableOutput("exec_recent_docs"),
  #     footer = "Últimos documentos legislativos importantes"
  #   )
  # ),

  # Data Quality and System Health
  fluidRow(
    # Data Quality Metrics
    box(
      title = "✅ Avaliação da Qualidade dos Dados",
      status = "primary",
      solidHeader = TRUE,
      width = 8,
      fluidRow(
        column(3,
          div(class = "quality-metric",
            h5("Completude", style = "margin: 0;"),
            div(class = "progress progress-sm",
              div(class = "progress-bar bg-success", style = "width: 94%", "94%")
            ),
            tags$small("Cobertura de metadados")
          )
        ),
        column(3,
          div(class = "quality-metric",
            h5("Atualidade", style = "margin: 0;"),
            div(class = "progress progress-sm",
              div(class = "progress-bar bg-info", style = "width: 87%", "87%")
            ),
            tags$small("Score de atualização")
          )
        ),
        column(3,
          div(class = "quality-metric",
            h5("Precisão", style = "margin: 0;"),
            div(class = "progress progress-sm",
              div(class = "progress-bar bg-warning", style = "width: 91%", "91%")
            ),
            tags$small("Taxa de validação")
          )
        ),
        column(3,
          div(class = "quality-metric",
            h5("Consistência", style = "margin: 0;"),
            div(class = "progress progress-sm",
              div(class = "progress-bar bg-danger", style = "width: 83%", "83%")
            ),
            tags$small("Padrões de dados")
          )
        )
      )
    ),
    # System Health - DISABLED (no server code)
    box(
      title = "🔧 Status do Sistema",
      status = "success",
      solidHeader = TRUE,
      width = 4,
      # TEMPORARILY DISABLED - Testing crash fix (orphaned output)
      # uiOutput("exec_system_health"),
      div(
        style = "padding: 20px; text-align: center;",
        p("Status do sistema em desenvolvimento", style = "color: #7f8c8d;")
      ),
      footer = "Monitoramento em tempo real"
    )
  )
)
