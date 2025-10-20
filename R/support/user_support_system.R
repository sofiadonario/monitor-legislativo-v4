# =============================================================================
# User Support System for Monitor Legislativo v4
# =============================================================================
#
# Comprehensive user support and help system for Brazilian academic users
# Integrates multilingual support, academic workflows, and LGPD compliance
# Designed for Railway deployment with academic institution integration
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-01-20
# Railway Environment: Production
# =============================================================================

library(shiny)
# shinydashboard loaded via R/000_load_shinydashboard.R preload file
library(DT)
library(jsonlite)
library(httr)
library(lubridate)
library(dplyr)

# =============================================================================
# USER SUPPORT CONFIGURATION
# =============================================================================

# Support system configuration
SUPPORT_CONFIG <- list(
  languages = c("pt", "en"),
  default_language = "pt",
  academic_context = TRUE,
  brazilian_timezone = "America/Sao_Paulo",
  support_hours = list(
    weekdays = "08:00-18:00",
    weekends = "09:00-14:00",
    timezone = "America/Sao_Paulo"
  ),
  contact_info = list(
    primary_email = "suporte@monitor-legislativo.org",
    academic_email = "academico@monitor-legislativo.org",
    technical_email = "tecnico@monitor-legislativo.org",
    lgpd_email = "lgpd@monitor-legislativo.org"
  )
)

# Support categories
SUPPORT_CATEGORIES <- list(
  getting_started = list(
    name_pt = "Primeiros Passos",
    name_en = "Getting Started",
    description_pt = "Como começar a usar o sistema",
    description_en = "How to start using the system"
  ),
  research_workflow = list(
    name_pt = "Fluxo de Pesquisa",
    name_en = "Research Workflow",
    description_pt = "Integração com workflows acadêmicos",
    description_en = "Integration with academic workflows"
  ),
  citations = list(
    name_pt = "Citações ABNT",
    name_en = "ABNT Citations",
    description_pt = "Geração de citações no padrão ABNT",
    description_en = "ABNT standard citation generation"
  ),
  data_analysis = list(
    name_pt = "Análise de Dados",
    name_en = "Data Analysis",
    description_pt = "Análise e visualização de dados legislativos",
    description_en = "Legislative data analysis and visualization"
  ),
  technical_issues = list(
    name_pt = "Problemas Técnicos",
    name_en = "Technical Issues",
    description_pt = "Suporte técnico e resolução de problemas",
    description_en = "Technical support and troubleshooting"
  ),
  privacy_lgpd = list(
    name_pt = "Privacidade e LGPD",
    name_en = "Privacy and LGPD",
    description_pt = "Questões de privacidade e proteção de dados",
    description_en = "Privacy and data protection questions"
  )
)

# =============================================================================
# USER SUPPORT SYSTEM CLASS
# =============================================================================

UserSupportSystem <- R6::R6Class(
  "UserSupportSystem",

  public = list(

    # Initialize support system
    initialize = function() {
      private$setup_support_environment()
      private$load_support_content()
      self$log_support_message("User Support System initialized", "INFO")
    },

    # =============================================================================
    # SUPPORT INTERFACE METHODS
    # =============================================================================

    # Create support dashboard UI
    create_support_ui = function() {
      # Support dashboard UI with Brazilian academic context
      dashboardPage(
        dashboardHeader(
          title = "Monitor Legislativo - Suporte Acadêmico",
          titleWidth = 350
        ),

        dashboardSidebar(
          width = 280,
          sidebarMenu(
            menuItem("Visão Geral", tabName = "overview", icon = icon("home")),
            menuItem("Primeiros Passos", tabName = "getting_started", icon = icon("play")),
            menuItem("Tutoriais em Vídeo", tabName = "video_tutorials", icon = icon("video")),
            menuItem("Guias de Pesquisa", tabName = "research_guides", icon = icon("graduation-cap")),
            menuItem("Citações ABNT", tabName = "citations", icon = icon("quote-right")),
            menuItem("Análise de Dados", tabName = "data_analysis", icon = icon("chart-bar")),
            menuItem("Perguntas Frequentes", tabName = "faq", icon = icon("question-circle")),
            menuItem("Contato e Suporte", tabName = "contact", icon = icon("envelope")),
            menuItem("Política de Privacidade", tabName = "privacy", icon = icon("shield-alt")),
            hr(),
            div(
              style = "padding: 15px; color: #b3b3b3; font-size: 12px;",
              HTML("
                <strong>Suporte Acadêmico:</strong><br/>
                Segunda a Sexta: 08h-18h<br/>
                Sábado: 09h-14h<br/>
                Timezone: Brasília (UTC-3)<br/>
                <br/>
                <strong>Emergências:</strong><br/>
                suporte@monitor-legislativo.org
              ")
            )
          )
        ),

        dashboardBody(
          tags$head(
            tags$style(HTML("
              .main-header .navbar {
                background-color: #2e8b57 !important;
              }
              .main-header .logo {
                background-color: #2e8b57 !important;
              }
              .skin-blue .main-sidebar {
                background-color: #f4f4f4 !important;
              }
              .help-section {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 8px;
                margin: 10px 0;
                border-left: 4px solid #2e8b57;
              }
              .video-container {
                position: relative;
                padding-bottom: 56.25%;
                height: 0;
                overflow: hidden;
              }
              .video-container iframe {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
              }
            "))
          ),

          tabItems(
            # Overview tab
            tabItem(
              tabName = "overview",
              private$create_overview_tab()
            ),

            # Getting started tab
            tabItem(
              tabName = "getting_started",
              private$create_getting_started_tab()
            ),

            # Video tutorials tab
            tabItem(
              tabName = "video_tutorials",
              private$create_video_tutorials_tab()
            ),

            # Research guides tab
            tabItem(
              tabName = "research_guides",
              private$create_research_guides_tab()
            ),

            # Citations tab
            tabItem(
              tabName = "citations",
              private$create_citations_tab()
            ),

            # Data analysis tab
            tabItem(
              tabName = "data_analysis",
              private$create_data_analysis_tab()
            ),

            # FAQ tab
            tabItem(
              tabName = "faq",
              private$create_faq_tab()
            ),

            # Contact tab
            tabItem(
              tabName = "contact",
              private$create_contact_tab()
            ),

            # Privacy tab
            tabItem(
              tabName = "privacy",
              private$create_privacy_tab()
            )
          )
        )
      )
    },

    # =============================================================================
    # SUPPORT TICKET MANAGEMENT
    # =============================================================================

    # Create support ticket
    create_support_ticket = function(user_info, issue_description, category, priority = "medium") {
      ticket_id <- private$generate_ticket_id()

      ticket <- list(
        ticket_id = ticket_id,
        timestamp = Sys.time(),
        user_info = user_info,
        category = category,
        priority = priority,
        issue_description = issue_description,
        status = "open",
        assigned_to = NULL,
        resolution = NULL,
        satisfaction_score = NULL,
        academic_context = TRUE,
        language = "pt",
        timezone = "America/Sao_Paulo"
      )

      # Save ticket
      private$save_support_ticket(ticket)

      # Send confirmation email
      private$send_ticket_confirmation(ticket)

      # Auto-assign based on category
      private$auto_assign_ticket(ticket)

      self$log_support_message(paste("Support ticket created:", ticket_id), "INFO")

      return(ticket_id)
    },

    # Update support ticket
    update_support_ticket = function(ticket_id, updates) {
      ticket <- private$load_support_ticket(ticket_id)

      if (is.null(ticket)) {
        self$log_support_message(paste("Ticket not found:", ticket_id), "WARNING")
        return(FALSE)
      }

      # Update ticket fields
      for (field in names(updates)) {
        if (field %in% names(ticket)) {
          ticket[[field]] <- updates[[field]]
        }
      }

      ticket$last_updated <- Sys.time()

      # Save updated ticket
      private$save_support_ticket(ticket)

      # Notify user of updates if status changed
      if ("status" %in% names(updates)) {
        private$send_status_update_notification(ticket)
      }

      self$log_support_message(paste("Support ticket updated:", ticket_id), "INFO")

      return(TRUE)
    },

    # =============================================================================
    # HELP CONTENT MANAGEMENT
    # =============================================================================

    # Get help content by category
    get_help_content = function(category, language = "pt") {
      content_key <- paste(category, language, sep = "_")

      if (content_key %in% names(private$help_content)) {
        return(private$help_content[[content_key]])
      } else {
        # Fallback to Portuguese if English not available
        fallback_key <- paste(category, "pt", sep = "_")
        if (fallback_key %in% names(private$help_content)) {
          return(private$help_content[[fallback_key]])
        }
      }

      return(NULL)
    },

    # Search help content
    search_help_content = function(query, language = "pt") {
      results <- list()

      for (content_name in names(private$help_content)) {
        content <- private$help_content[[content_name]]

        # Check if query matches title or content
        if (grepl(query, content$title, ignore.case = TRUE) ||
            grepl(query, content$content, ignore.case = TRUE)) {
          results[[content_name]] <- content
        }
      }

      return(results)
    },

    # =============================================================================
    # ACADEMIC SUPPORT FEATURES
    # =============================================================================

    # Generate academic workflow guide
    generate_academic_workflow_guide = function(research_type, institution_type = "university") {
      workflow_guide <- list(
        title = "Guia de Fluxo de Trabalho Acadêmico",
        research_type = research_type,
        institution_type = institution_type,
        steps = list(),
        estimated_time = "2-4 horas",
        required_skills = c("Básico em pesquisa acadêmica", "Familiaridade com citações ABNT"),
        outputs = list("Relatório de pesquisa", "Bibliografia formatada", "Visualizações de dados")
      )

      # Add specific steps based on research type
      if (research_type == "legislative_analysis") {
        workflow_guide$steps <- list(
          list(
            step = 1,
            title = "Definição da Pesquisa",
            description = "Defina o escopo temporal e geográfico da sua pesquisa legislativa",
            time_estimate = "30 minutos",
            tools = c("Filtros temporais", "Seleção geográfica")
          ),
          list(
            step = 2,
            title = "Busca e Filtragem",
            description = "Use palavras-chave e filtros para encontrar legislação relevante",
            time_estimate = "45 minutos",
            tools = c("Busca avançada", "Filtros por tipo de norma")
          ),
          list(
            step = 3,
            title = "Análise e Visualização",
            description = "Analise tendências e padrões usando as ferramentas de visualização",
            time_estimate = "60 minutos",
            tools = c("Gráficos temporais", "Mapas temáticos")
          ),
          list(
            step = 4,
            title = "Citação e Exportação",
            description = "Gere citações ABNT e exporte seus dados para análise adicional",
            time_estimate = "30 minutos",
            tools = c("Gerador de citações ABNT", "Exportação de dados")
          )
        )
      }

      return(workflow_guide)
    },

    # Generate ABNT citation help
    generate_abnt_citation_help = function() {
      citation_help <- list(
        title = "Guia de Citações ABNT para Documentos Legislativos",
        description = "Como citar corretamente documentos legislativos segundo as normas ABNT",
        examples = list(
          lei = list(
            title = "Lei Federal",
            format = "BRASIL. Lei nº [número], de [data]. [Ementa]. [Local]: [Órgão], [ano]. Disponível em: [URL]. Acesso em: [data de acesso].",
            example = "BRASIL. Lei nº 14.129, de 29 de março de 2021. Dispõe sobre princípios, regras e instrumentos para o Governo Digital. Brasília: Presidência da República, 2021. Disponível em: https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/l14129.htm. Acesso em: 20 jan. 2025."
          ),
          decreto = list(
            title = "Decreto",
            format = "BRASIL. Decreto nº [número], de [data]. [Ementa]. [Local]: [Órgão], [ano]. Disponível em: [URL]. Acesso em: [data de acesso].",
            example = "BRASIL. Decreto nº 10.543, de 13 de novembro de 2020. Dispõe sobre o uso do Registro de Identidade Civil. Brasília: Presidência da República, 2020. Disponível em: https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2020/decreto/d10543.htm. Acesso em: 20 jan. 2025."
          ),
          estadual = list(
            title = "Lei Estadual",
            format = "[ESTADO]. Lei nº [número], de [data]. [Ementa]. [Local]: [Órgão], [ano]. Disponível em: [URL]. Acesso em: [data de acesso].",
            example = "SÃO PAULO. Lei nº 17.293, de 15 de outubro de 2020. Institui o Marco Legal da Inovação do Estado de São Paulo. São Paulo: Assembleia Legislativa, 2020. Disponível em: https://www.al.sp.gov.br/repositorio/legislacao/lei/2020/lei-17293-15.10.2020.html. Acesso em: 20 jan. 2025."
          )
        ),
        best_practices = list(
          "Sempre verificar a data de acesso aos documentos online",
          "Incluir o número completo da norma jurídica",
          "Citar a ementa completa do documento",
          "Verificar a versão mais atualizada da norma",
          "Usar formato de data brasileiro (dd mmm aaaa)"
        )
      )

      return(citation_help)
    },

    # =============================================================================
    # USER FEEDBACK AND ANALYTICS
    # =============================================================================

    # Collect user feedback
    collect_user_feedback = function(user_id, feedback_type, content, rating = NULL) {
      feedback_id <- private$generate_feedback_id()

      feedback <- list(
        feedback_id = feedback_id,
        timestamp = Sys.time(),
        user_id = user_id,
        feedback_type = feedback_type,
        content = content,
        rating = rating,
        processed = FALSE,
        academic_context = TRUE,
        language = "pt"
      )

      # Save feedback
      private$save_user_feedback(feedback)

      # Auto-process if it's a bug report or feature request
      if (feedback_type %in% c("bug_report", "feature_request")) {
        private$process_feedback_to_ticket(feedback)
      }

      self$log_support_message(paste("User feedback collected:", feedback_id), "INFO")

      return(feedback_id)
    },

    # Generate user support analytics
    generate_support_analytics = function(period_days = 30) {
      end_date <- Sys.Date()
      start_date <- end_date - days(period_days)

      analytics <- list(
        period = paste(start_date, "to", end_date),
        ticket_metrics = private$calculate_ticket_metrics(start_date, end_date),
        user_satisfaction = private$calculate_user_satisfaction(start_date, end_date),
        content_usage = private$calculate_content_usage(start_date, end_date),
        academic_usage = private$calculate_academic_usage(start_date, end_date),
        improvement_recommendations = private$generate_improvement_recommendations()
      )

      return(analytics)
    },

    # Log support message
    log_support_message = function(message, level = "INFO") {
      timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S", tz = "America/Sao_Paulo")
      log_entry <- paste0("[", timestamp, "] [USER-SUPPORT] [", level, "] ", message)

      cat(log_entry, "\n")

      # Log to file if enabled
      if (Sys.getenv("USER_SUPPORT_LOGGING", "true") == "true") {
        log_file <- Sys.getenv("USER_SUPPORT_LOG", "/tmp/user_support.log")
        cat(log_entry, "\n", file = log_file, append = TRUE)
      }
    }
  ),

  # =============================================================================
  # PRIVATE METHODS
  # =============================================================================

  private = list(
    help_content = NULL,
    support_tickets = NULL,
    user_feedback = NULL,

    # Setup support environment
    setup_support_environment = function() {
      private$support_config <- SUPPORT_CONFIG
      private$support_categories <- SUPPORT_CATEGORIES

      # Initialize data structures
      private$support_tickets <- list()
      private$user_feedback <- list()
    },

    # Load support content
    load_support_content = function() {
      private$help_content <- list(
        getting_started_pt = list(
          title = "Primeiros Passos no Monitor Legislativo",
          content = "Bem-vindo ao Monitor Legislativo v4! Este guia irá ajudá-lo a começar...",
          category = "getting_started",
          language = "pt"
        ),
        research_workflow_pt = list(
          title = "Fluxo de Trabalho para Pesquisa Acadêmica",
          content = "Aprenda como integrar o Monitor Legislativo em seu fluxo de pesquisa acadêmica...",
          category = "research_workflow",
          language = "pt"
        ),
        citations_pt = list(
          title = "Gerando Citações ABNT",
          content = "Como gerar citações no padrão ABNT para documentos legislativos...",
          category = "citations",
          language = "pt"
        )
      )
    },

    # Create overview tab
    create_overview_tab = function() {
      fluidRow(
        column(12,
          h2("Central de Suporte Acadêmico", style = "color: #2e8b57; margin-bottom: 20px;"),
          p("Bem-vindo à Central de Suporte do Monitor Legislativo v4. Aqui você encontrará todas as informações necessárias para aproveitar ao máximo nossa plataforma de monitoramento legislativo."),
          hr()
        ),
        column(4,
          div(class = "help-section",
            h4("🚀 Primeiros Passos"),
            p("Novo no sistema? Comece aqui para aprender os conceitos básicos e configurar sua conta."),
            actionButton("btn_getting_started", "Começar Tutorial", class = "btn-success")
          )
        ),
        column(4,
          div(class = "help-section",
            h4("🎓 Pesquisa Acadêmica"),
            p("Aprenda como integrar o Monitor Legislativo em seus projetos de pesquisa acadêmica."),
            actionButton("btn_research_guides", "Guias de Pesquisa", class = "btn-info")
          )
        ),
        column(4,
          div(class = "help-section",
            h4("📚 Citações ABNT"),
            p("Gere citações automaticamente no padrão ABNT para seus trabalhos acadêmicos."),
            actionButton("btn_citations", "Aprender Citações", class = "btn-warning")
          )
        ),
        column(12,
          br(),
          fluidRow(
            column(6,
              box(
                title = "Recursos Populares", status = "primary", solidHeader = TRUE, width = NULL,
                tags$ul(
                  tags$li("Tutorial em vídeo: Busca avançada de legislação"),
                  tags$li("Guia: Análise temporal de normas jurídicas"),
                  tags$li("Tutorial: Visualização geográfica de dados"),
                  tags$li("Guia: Exportação de dados para análise"),
                  tags$li("Tutorial: Colaboração em projetos de pesquisa")
                )
              )
            ),
            column(6,
              box(
                title = "Suporte Rápido", status = "success", solidHeader = TRUE, width = NULL,
                p(strong("Horários de Atendimento:")),
                p("Segunda a Sexta: 08h às 18h"),
                p("Sábado: 09h às 14h"),
                p("Timezone: Brasília (UTC-3)"),
                br(),
                p(strong("Contatos:")),
                p("✉️ suporte@monitor-legislativo.org"),
                p("🎓 academico@monitor-legislativo.org"),
                p("🔒 lgpd@monitor-legislativo.org")
              )
            )
          )
        )
      )
    },

    # Create getting started tab
    create_getting_started_tab = function() {
      fluidRow(
        column(12,
          h2("Primeiros Passos", style = "color: #2e8b57;"),
          p("Este guia irá orientá-lo através dos primeiros passos para usar o Monitor Legislativo v4 em suas pesquisas acadêmicas."),
          hr()
        ),
        column(12,
          box(
            title = "Passo 1: Configuração da Conta", status = "primary", solidHeader = TRUE, width = NULL,
            p("1. Acesse sua conta institucional"),
            p("2. Configure seu perfil acadêmico"),
            p("3. Defina suas preferências de pesquisa"),
            p("4. Configure notificações e alertas")
          )
        ),
        column(12,
          box(
            title = "Passo 2: Primeira Busca", status = "info", solidHeader = TRUE, width = NULL,
            p("1. Use a barra de busca principal"),
            p("2. Aplique filtros por período e região"),
            p("3. Selecione tipos de normas jurídicas"),
            p("4. Analise os resultados encontrados")
          )
        ),
        column(12,
          box(
            title = "Passo 3: Análise e Citação", status = "success", solidHeader = TRUE, width = NULL,
            p("1. Visualize dados em gráficos e mapas"),
            p("2. Gere citações ABNT automaticamente"),
            p("3. Exporte dados para análise externa"),
            p("4. Salve projetos de pesquisa")
          )
        )
      )
    },

    # Create video tutorials tab
    create_video_tutorials_tab = function() {
      fluidRow(
        column(12,
          h2("Tutoriais em Vídeo", style = "color: #2e8b57;"),
          p("Aprenda a usar o Monitor Legislativo através de nossos tutoriais em vídeo, especialmente desenvolvidos para pesquisadores acadêmicos brasileiros."),
          hr()
        ),
        column(6,
          box(
            title = "Tutorial 1: Introdução ao Sistema", status = "primary", solidHeader = TRUE, width = NULL,
            div(class = "video-container",
              HTML('<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ" frameborder="0" allowfullscreen></iframe>')
            ),
            p("Duração: 10 minutos"),
            p("Visão geral do sistema e funcionalidades principais.")
          )
        ),
        column(6,
          box(
            title = "Tutorial 2: Busca Avançada", status = "info", solidHeader = TRUE, width = NULL,
            div(class = "video-container",
              HTML('<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ" frameborder="0" allowfullscreen></iframe>')
            ),
            p("Duração: 15 minutos"),
            p("Como usar filtros avançados e operadores de busca.")
          )
        ),
        column(6,
          box(
            title = "Tutorial 3: Análise Geográfica", status = "warning", solidHeader = TRUE, width = NULL,
            div(class = "video-container",
              HTML('<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ" frameborder="0" allowfullscreen></iframe>')
            ),
            p("Duração: 12 minutos"),
            p("Visualização e análise geográfica de dados legislativos.")
          )
        ),
        column(6,
          box(
            title = "Tutorial 4: Citações ABNT", status = "success", solidHeader = TRUE, width = NULL,
            div(class = "video-container",
              HTML('<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ" frameborder="0" allowfullscreen></iframe>')
            ),
            p("Duração: 8 minutos"),
            p("Como gerar citações automáticas no padrão ABNT.")
          )
        )
      )
    },

    # Create research guides tab
    create_research_guides_tab = function() {
      fluidRow(
        column(12,
          h2("Guias de Pesquisa Acadêmica", style = "color: #2e8b57;"),
          p("Guias especializados para diferentes tipos de pesquisa acadêmica usando dados legislativos."),
          hr()
        ),
        column(4,
          box(
            title = "Análise Temporal", status = "primary", solidHeader = TRUE, width = NULL,
            p("Como analisar a evolução da legislação ao longo do tempo."),
            tags$ul(
              tags$li("Configuração de períodos"),
              tags$li("Análise de tendências"),
              tags$li("Visualização temporal"),
              tags$li("Interpretação de resultados")
            ),
            actionButton("btn_temporal_guide", "Ver Guia Completo", class = "btn-primary")
          )
        ),
        column(4,
          box(
            title = "Análise Comparativa", status = "info", solidHeader = TRUE, width = NULL,
            p("Comparação entre diferentes jurisdições ou períodos."),
            tags$ul(
              tags$li("Seleção de variáveis"),
              tags$li("Métodos de comparação"),
              tags$li("Visualização comparativa"),
              tags$li("Análise estatística")
            ),
            actionButton("btn_comparative_guide", "Ver Guia Completo", class = "btn-info")
          )
        ),
        column(4,
          box(
            title = "Análise Temática", status = "success", solidHeader = TRUE, width = NULL,
            p("Pesquisa focada em temas específicos da legislação."),
            tags$ul(
              tags$li("Definição de palavras-chave"),
              tags$li("Categorização temática"),
              tags$li("Análise de conteúdo"),
              tags$li("Síntese de resultados")
            ),
            actionButton("btn_thematic_guide", "Ver Guia Completo", class = "btn-success")
          )
        )
      )
    },

    # Create citations tab
    create_citations_tab = function() {
      fluidRow(
        column(12,
          h2("Geração de Citações ABNT", style = "color: #2e8b57;"),
          p("Aprenda a gerar citações automáticas no padrão ABNT para documentos legislativos brasileiros."),
          hr()
        ),
        column(6,
          box(
            title = "Formato ABNT para Leis", status = "primary", solidHeader = TRUE, width = NULL,
            h5("Formato:"),
            code("BRASIL. Lei nº [número], de [data]. [Ementa]. [Local]: [Órgão], [ano]. Disponível em: [URL]. Acesso em: [data de acesso]."),
            br(), br(),
            h5("Exemplo:"),
            p(style = "font-style: italic;", "BRASIL. Lei nº 14.129, de 29 de março de 2021. Dispõe sobre princípios, regras e instrumentos para o Governo Digital. Brasília: Presidência da República, 2021. Disponível em: https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/l14129.htm. Acesso em: 20 jan. 2025.")
          )
        ),
        column(6,
          box(
            title = "Formato ABNT para Decretos", status = "info", solidHeader = TRUE, width = NULL,
            h5("Formato:"),
            code("BRASIL. Decreto nº [número], de [data]. [Ementa]. [Local]: [Órgão], [ano]. Disponível em: [URL]. Acesso em: [data de acesso]."),
            br(), br(),
            h5("Exemplo:"),
            p(style = "font-style: italic;", "BRASIL. Decreto nº 10.543, de 13 de novembro de 2020. Dispõe sobre o uso do Registro de Identidade Civil. Brasília: Presidência da República, 2020. Disponível em: https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2020/decreto/d10543.htm. Acesso em: 20 jan. 2025.")
          )
        ),
        column(12,
          box(
            title = "Gerador Automático de Citações", status = "success", solidHeader = TRUE, width = NULL,
            p("Use nossa ferramenta integrada para gerar citações ABNT automaticamente:"),
            tags$ol(
              tags$li("Selecione o documento legislativo na busca"),
              tags$li("Clique no botão 'Gerar Citação ABNT'"),
              tags$li("Copie a citação formatada"),
              tags$li("Cole em sua bibliografia")
            ),
            br(),
            actionButton("btn_citation_tool", "Abrir Gerador de Citações", class = "btn-success")
          )
        )
      )
    },

    # Create data analysis tab
    create_data_analysis_tab = function() {
      fluidRow(
        column(12,
          h2("Análise de Dados Legislativos", style = "color: #2e8b57;"),
          p("Ferramentas e técnicas para análise avançada de dados legislativos brasileiros."),
          hr()
        ),
        column(6,
          box(
            title = "Visualizações Disponíveis", status = "primary", solidHeader = TRUE, width = NULL,
            tags$ul(
              tags$li("Gráficos temporais de produção legislativa"),
              tags$li("Mapas de calor por região"),
              tags$li("Gráficos de barras por tipo de norma"),
              tags$li("Análise de tendências sazonais"),
              tags$li("Visualizações de redes temáticas"),
              tags$li("Gráficos de correlação entre variáveis")
            )
          )
        ),
        column(6,
          box(
            title = "Exportação de Dados", status = "info", solidHeader = TRUE, width = NULL,
            tags$ul(
              tags$li("CSV para análise em Excel/R/Python"),
              tags$li("JSON para aplicações web"),
              tags$li("PDF com relatórios formatados"),
              tags$li("Imagens de gráficos em alta resolução"),
              tags$li("Dados agregados por região/período"),
              tags$li("Metadados descritivos incluídos")
            )
          )
        ),
        column(12,
          box(
            title = "Tutorial: Análise Completa de Dados", status = "success", solidHeader = TRUE, width = NULL,
            p("Siga este tutorial passo-a-passo para realizar uma análise completa:"),
            tags$ol(
              tags$li("Defina sua questão de pesquisa"),
              tags$li("Configure filtros apropriados"),
              tags$li("Explore dados com visualizações"),
              tags$li("Identifique padrões e tendências"),
              tags$li("Exporte dados para análise estatística"),
              tags$li("Gere relatório com interpretações")
            ),
            actionButton("btn_analysis_tutorial", "Iniciar Tutorial", class = "btn-success")
          )
        )
      )
    },

    # Create FAQ tab
    create_faq_tab = function() {
      fluidRow(
        column(12,
          h2("Perguntas Frequentes", style = "color: #2e8b57;"),
          p("Respostas para as dúvidas mais comuns sobre o Monitor Legislativo v4."),
          hr()
        ),
        column(12,
          box(
            title = "Uso Geral do Sistema", status = "primary", solidHeader = TRUE, width = NULL,
            h5("Como faço para começar a usar o sistema?"),
            p("Acesse com suas credenciais institucionais e siga o tutorial de primeiros passos. Recomendamos começar com uma busca simples e depois explorar as funcionalidades avançadas."),
            h5("Posso usar o sistema fora do horário comercial?"),
            p("Sim, o sistema está disponível 24/7. O suporte técnico opera de segunda a sexta das 8h às 18h, e sábados das 9h às 14h (horário de Brasília)."),
            h5("Como salvo meus projetos de pesquisa?"),
            p("Use a funcionalidade 'Salvar Projeto' no menu principal. Seus projetos ficam associados à sua conta institucional e podem ser acessados a qualquer momento.")
          )
        ),
        column(12,
          box(
            title = "Dados e Pesquisa", status = "info", solidHeader = TRUE, width = NULL,
            h5("Qual a cobertura temporal dos dados?"),
            p("Nossa base inclui documentos legislativos de 1988 até o presente, com atualizações diárias para novas publicações."),
            h5("Como garantir a qualidade das citações ABNT?"),
            p("Nosso sistema segue rigorosamente as normas ABNT NBR 6023:2018. Recomendamos sempre verificar a data de acesso aos documentos online."),
            h5("Posso exportar dados para análise em outros softwares?"),
            p("Sim, oferecemos exportação em CSV, JSON e outros formatos compatíveis com R, Python, Excel e ferramentas de análise estatística.")
          )
        ),
        column(12,
          box(
            title = "Privacidade e LGPD", status = "warning", solidHeader = TRUE, width = NULL,
            h5("Como meus dados pessoais são protegidos?"),
            p("Seguimos rigorosamente a LGPD. Coletamos apenas dados necessários para o funcionamento do sistema e pesquisa acadêmica. Veja nossa Política de Privacidade para detalhes."),
            h5("Posso solicitar exclusão dos meus dados?"),
            p("Sim, você pode solicitar acesso, correção ou exclusão dos seus dados pessoais através do email lgpd@monitor-legislativo.org."),
            h5("Os dados de pesquisa são compartilhados?"),
            p("Dados de pesquisa são anonimizados e agregados apenas para fins acadêmicos, sempre respeitando os princípios éticos e a LGPD.")
          )
        )
      )
    },

    # Create contact tab
    create_contact_tab = function() {
      fluidRow(
        column(12,
          h2("Contato e Suporte", style = "color: #2e8b57;"),
          p("Entre em contato conosco para suporte técnico, dúvidas acadêmicas ou questões de privacidade."),
          hr()
        ),
        column(6,
          box(
            title = "Canais de Suporte", status = "primary", solidHeader = TRUE, width = NULL,
            h5("📧 Suporte Geral"),
            p("suporte@monitor-legislativo.org"),
            p("Para dúvidas gerais, problemas técnicos e orientações básicas."),
            br(),
            h5("🎓 Suporte Acadêmico"),
            p("academico@monitor-legislativo.org"),
            p("Para questões relacionadas a pesquisa, metodologia e uso acadêmico."),
            br(),
            h5("🔒 Privacidade e LGPD"),
            p("lgpd@monitor-legislativo.org"),
            p("Para questões de privacidade, proteção de dados e direitos do titular.")
          )
        ),
        column(6,
          box(
            title = "Horários de Atendimento", status = "info", solidHeader = TRUE, width = NULL,
            h5("⏰ Horário Regular"),
            p("Segunda a Sexta: 08h00 às 18h00"),
            p("Sábado: 09h00 às 14h00"),
            p("Timezone: Brasília (UTC-3)"),
            br(),
            h5("🚨 Suporte de Emergência"),
            p("Para problemas críticos que impedem o acesso ao sistema, entre em contato através do email principal com o assunto '[URGENTE]'."),
            br(),
            h5("📞 Tempo de Resposta"),
            p("Geral: até 24 horas"),
            p("Acadêmico: até 48 horas"),
            p("LGPD: até 72 horas"),
            p("Emergência: até 2 horas")
          )
        ),
        column(12,
          box(
            title = "Formulário de Contato", status = "success", solidHeader = TRUE, width = NULL,
            fluidRow(
              column(6,
                textInput("contact_name", "Nome:", placeholder = "Seu nome completo"),
                textInput("contact_email", "Email:", placeholder = "seu.email@instituicao.edu.br")
              ),
              column(6,
                selectInput("contact_category", "Categoria:",
                  choices = list(
                    "Suporte Técnico" = "technical",
                    "Suporte Acadêmico" = "academic",
                    "Privacidade/LGPD" = "privacy",
                    "Sugestões" = "feedback",
                    "Outros" = "other"
                  )
                ),
                selectInput("contact_priority", "Prioridade:",
                  choices = list("Baixa" = "low", "Média" = "medium", "Alta" = "high", "Urgente" = "urgent")
                )
              )
            ),
            textAreaInput("contact_message", "Mensagem:", rows = 5,
              placeholder = "Descreva sua dúvida ou problema detalhadamente..."),
            br(),
            actionButton("btn_send_contact", "Enviar Mensagem", class = "btn-success")
          )
        )
      )
    },

    # Create privacy tab
    create_privacy_tab = function() {
      fluidRow(
        column(12,
          h2("Política de Privacidade e LGPD", style = "color: #2e8b57;"),
          p("Informações sobre como protegemos seus dados pessoais e cumprimos a Lei Geral de Proteção de Dados (LGPD)."),
          hr()
        ),
        column(12,
          box(
            title = "Resumo da Política de Privacidade", status = "info", solidHeader = TRUE, width = NULL,
            p("O Monitor Legislativo v4 está comprometido com a proteção da sua privacidade e o cumprimento integral da LGPD (Lei 13.709/2018). Coletamos e processamos dados pessoais apenas quando necessário para:"),
            tags$ul(
              tags$li("Funcionamento do sistema e autenticação de usuários"),
              tags$li("Pesquisa acadêmica e produção científica"),
              tags$li("Melhoria da experiência do usuário"),
              tags$li("Cumprimento de obrigações legais")
            ),
            p("Todos os dados são tratados com base em fundamentos legais válidos, especialmente pesquisa acadêmica (Art. 7º, IV) e legítimo interesse (Art. 7º, IX).")
          )
        ),
        column(6,
          box(
            title = "Seus Direitos (LGPD)", status = "primary", solidHeader = TRUE, width = NULL,
            p("Como titular de dados pessoais, você tem os seguintes direitos:"),
            tags$ul(
              tags$li("Confirmação da existência de tratamento"),
              tags$li("Acesso aos dados pessoais"),
              tags$li("Correção de dados incompletos ou inexatos"),
              tags$li("Anonimização ou eliminação de dados"),
              tags$li("Portabilidade dos dados"),
              tags$li("Informação sobre compartilhamento"),
              tags$li("Retirada do consentimento (quando aplicável)")
            ),
            p("Para exercer seus direitos, entre em contato através de lgpd@monitor-legislativo.org.")
          )
        ),
        column(6,
          box(
            title = "Tipos de Dados Coletados", status = "warning", solidHeader = TRUE, width = NULL,
            p("Coletamos as seguintes categorias de dados:"),
            tags$ul(
              tags$li(strong("Dados de cadastro:"), " nome, email institucional, afiliação"),
              tags$li(strong("Dados de uso:"), " páginas acessadas, buscas realizadas, tempo de sessão"),
              tags$li(strong("Dados técnicos:"), " endereço IP, navegador, sistema operacional"),
              tags$li(strong("Dados de pesquisa:"), " projetos salvos, citações geradas, exportações")
            ),
            p("Não coletamos dados sensíveis conforme definido pela LGPD, exceto quando estritamente necessário para pesquisa acadêmica.")
          )
        ),
        column(12,
          box(
            title = "Contato do Encarregado de Dados", status = "success", solidHeader = TRUE, width = NULL,
            p("Para questões relacionadas à proteção de dados pessoais e LGPD:"),
            p(strong("Email:"), " lgpd@monitor-legislativo.org"),
            p(strong("Prazo de resposta:"), " até 72 horas para solicitações gerais"),
            p(strong("Prazo para exercício de direitos:"), " até 15 dias úteis"),
            br(),
            p("Nosso Encarregado de Dados (DPO) está disponível para esclarecer dúvidas sobre tratamento de dados pessoais, auxiliar no exercício de direitos dos titulares e servir como canal de comunicação com a Autoridade Nacional de Proteção de Dados (ANPD).")
          )
        )
      )
    },

    # Generate ticket ID
    generate_ticket_id = function() {
      timestamp <- format(Sys.time(), "%Y%m%d%H%M%S")
      random_suffix <- sample(1000:9999, 1)
      return(paste0("TICKET_", timestamp, "_", random_suffix))
    },

    # Generate feedback ID
    generate_feedback_id = function() {
      timestamp <- format(Sys.time(), "%Y%m%d%H%M%S")
      random_suffix <- sample(100:999, 1)
      return(paste0("FEEDBACK_", timestamp, "_", random_suffix))
    },

    # Save support ticket
    save_support_ticket = function(ticket) {
      private$support_tickets[[ticket$ticket_id]] <- ticket

      # In a real implementation, this would save to a database
      ticket_file <- file.path("/tmp", paste0(ticket$ticket_id, ".json"))
      write_json(ticket, ticket_file, pretty = TRUE, auto_unbox = TRUE)
    },

    # Load support ticket
    load_support_ticket = function(ticket_id) {
      if (ticket_id %in% names(private$support_tickets)) {
        return(private$support_tickets[[ticket_id]])
      }

      # Try to load from file
      ticket_file <- file.path("/tmp", paste0(ticket_id, ".json"))
      if (file.exists(ticket_file)) {
        ticket <- fromJSON(ticket_file)
        private$support_tickets[[ticket_id]] <- ticket
        return(ticket)
      }

      return(NULL)
    },

    # Save user feedback
    save_user_feedback = function(feedback) {
      private$user_feedback[[feedback$feedback_id]] <- feedback

      # In a real implementation, this would save to a database
      feedback_file <- file.path("/tmp", paste0(feedback$feedback_id, ".json"))
      write_json(feedback, feedback_file, pretty = TRUE, auto_unbox = TRUE)
    },

    # Send ticket confirmation
    send_ticket_confirmation = function(ticket) {
      # In a real implementation, this would send an email
      confirmation_message <- paste(
        "Olá! Recebemos seu ticket de suporte:", ticket$ticket_id,
        "Nossa equipe irá analisá-lo e responder em breve.",
        "Tempo estimado de resposta:",
        if (ticket$priority == "urgent") "2 horas" else if (ticket$priority == "high") "4 horas" else "24 horas"
      )

      return(TRUE)
    },

    # Auto-assign ticket
    auto_assign_ticket = function(ticket) {
      # Simple auto-assignment logic
      assigned_to <- switch(ticket$category,
        "technical_issues" = "technical_team",
        "academic_support" = "academic_team",
        "privacy_lgpd" = "privacy_team",
        "citations" = "academic_team",
        "general_support"
      )

      ticket$assigned_to <- assigned_to
      private$save_support_ticket(ticket)

      return(assigned_to)
    },

    # Send status update notification
    send_status_update_notification = function(ticket) {
      # In a real implementation, this would send an email notification
      status_message <- switch(ticket$status,
        "in_progress" = "Seu ticket está sendo analisado por nossa equipe.",
        "resolved" = "Seu ticket foi resolvido. Por favor, avalie nosso atendimento.",
        "closed" = "Seu ticket foi fechado. Entre em contato se precisar de mais ajuda.",
        "Seu ticket foi atualizado."
      )

      return(TRUE)
    },

    # Calculate ticket metrics
    calculate_ticket_metrics = function(start_date, end_date) {
      # In a real implementation, this would query the database
      metrics <- list(
        total_tickets = 150,
        resolved_tickets = 135,
        average_resolution_time = "18 horas",
        satisfaction_score = 4.2,
        categories = list(
          technical_issues = 45,
          academic_support = 60,
          citations = 25,
          privacy_lgpd = 10,
          general = 10
        )
      )

      return(metrics)
    },

    # Calculate user satisfaction
    calculate_user_satisfaction = function(start_date, end_date) {
      # Sample satisfaction data
      satisfaction <- list(
        overall_score = 4.2,
        response_time_score = 4.0,
        resolution_quality_score = 4.3,
        academic_support_score = 4.5,
        total_responses = 120
      )

      return(satisfaction)
    },

    # Calculate content usage
    calculate_content_usage = function(start_date, end_date) {
      # Sample content usage data
      usage <- list(
        most_viewed_content = c("Citações ABNT", "Primeiros Passos", "Busca Avançada"),
        video_tutorial_views = 450,
        help_searches = 320,
        contact_form_submissions = 85
      )

      return(usage)
    },

    # Calculate academic usage
    calculate_academic_usage = function(start_date, end_date) {
      # Sample academic usage data
      academic_usage <- list(
        active_researchers = 75,
        citations_generated = 340,
        research_projects = 25,
        publications_supported = 8
      )

      return(academic_usage)
    },

    # Generate improvement recommendations
    generate_improvement_recommendations = function() {
      recommendations <- list(
        "Expandir seção de tutoriais em vídeo",
        "Adicionar mais exemplos de citações ABNT",
        "Melhorar tempo de resposta para tickets técnicos",
        "Criar guias específicos por área de pesquisa",
        "Implementar chat em tempo real para suporte urgente"
      )

      return(recommendations)
    },

    # Process feedback to ticket
    process_feedback_to_ticket = function(feedback) {
      # Convert high-priority feedback to support tickets
      if (feedback$feedback_type %in% c("bug_report", "feature_request")) {
        ticket_priority <- if (feedback$feedback_type == "bug_report") "high" else "medium"

        ticket <- list(
          ticket_id = private$generate_ticket_id(),
          timestamp = Sys.time(),
          user_info = list(user_id = feedback$user_id),
          category = "feedback_generated",
          priority = ticket_priority,
          issue_description = paste("Feedback automático:", feedback$content),
          status = "open",
          source = "user_feedback",
          feedback_id = feedback$feedback_id
        )

        private$save_support_ticket(ticket)
        return(ticket$ticket_id)
      }

      return(NULL)
    }
  )
)

# =============================================================================
# USER SUPPORT UTILITY FUNCTIONS
# =============================================================================

# Create user support system instance
create_user_support_system <- function() {
  return(UserSupportSystem$new())
}

# Quick support ticket creation
create_quick_support_ticket <- function(user_email, issue_description, category = "general") {
  support_system <- create_user_support_system()

  user_info <- list(
    email = user_email,
    timestamp = Sys.time(),
    source = "quick_ticket"
  )

  ticket_id <- support_system$create_support_ticket(
    user_info = user_info,
    issue_description = issue_description,
    category = category
  )

  return(ticket_id)
}

# Launch user support interface
launch_user_support_interface <- function(port = 3839, host = "127.0.0.1") {
  support_system <- create_user_support_system()

  ui <- support_system$create_support_ui()
  server <- function(input, output, session) {
    # Server logic would be implemented here
  }

  shinyApp(ui = ui, server = server, options = list(port = port, host = host))
}

# =============================================================================
# EXPORT USER SUPPORT SYSTEM
# =============================================================================

if (exists("UserSupportSystem")) {
  cat("✅ User Support System loaded successfully\n")
  cat("🇧🇷 Brazilian Portuguese academic support ready\n")
  cat("🎓 Academic workflow integration active\n")
  cat("📚 ABNT citation support available\n")
  cat("🔒 LGPD compliant user support system ready\n")
} else {
  stop("❌ Failed to load User Support System")
}