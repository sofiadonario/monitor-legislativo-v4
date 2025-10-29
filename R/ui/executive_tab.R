# Executive Summary Tab UI
# Monitor Legislativo v4 - Executive Dashboard Interface
# ======================================================
# v79: FIX for extent=0 error by removing nested bslib::layout_columns

div(
  # Strategic Insights Panel - Top Priority Information
  card(
    card_header("📊 Panorama da Legislação Brasileira"),
    class = "bg-primary text-white",
    # Replaced nested layout_columns with a standard bslib card layout
    card_body(
      fluidRow(
        column(4,
          card(
            card_header("Áreas de Foco Atual"),
            uiOutput("exec_focus_areas")
          )
        ),
        column(4,
          card(
            card_header("Atividade Legislativa"),
            uiOutput("exec_activity_summary")
          )
        ),
        column(4,
          card(
            card_header("Qualidade da Cobertura"),
            uiOutput("exec_coverage_quality")
          )
        )
      )
    )
  ),

  # Critical Metrics Dashboard - Enhanced Value Boxes
  layout_columns(
    col_widths = c(3, 3, 3, 3),
    uiOutput("exec_total_docs"),
    uiOutput("exec_states_coverage"),
    uiOutput("exec_recent_additions"),
    uiOutput("exec_data_freshness")
  ),

  # Key Performance Indicators
  layout_columns(
    col_widths = c(2, 2, 2, 2, 2, 2),
    uiOutput("exec_federal_docs"),
    uiOutput("exec_state_docs"),
    uiOutput("exec_municipal_docs"),
    uiOutput("exec_jurisprudence_docs"),
    uiOutput("exec_doctrine_docs"),
    uiOutput("exec_active_themes")
  ),

  # Data Quality and System Health
  layout_columns(
    col_widths = c(8, 4),
    # Data Quality Metrics
    card(
      card_header("✅ Avaliação da Qualidade dos Dados"),
      # Replaced nested layout_columns with a standard fluidRow
      card_body(
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
      )
    ),
    # System Health
    card(
      card_header("🔧 Status do Sistema"),
      div(
        style = "padding: 20px; text-align: center;",
        p("Status do sistema em desenvolvimento", style = "color: #7f8c8d;")
      ),
      card_footer("Monitoramento em tempo real")
    )
  )
)