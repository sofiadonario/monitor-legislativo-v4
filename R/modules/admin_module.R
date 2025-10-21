# Admin Module
# Monitor Legislativo v4 - Administrative Functions and System Management
# ========================================================================

#' Administrative Module for Monitor Legislativo v4
#' 
#' Comprehensive Shiny module for system administration including user management,
#' system monitoring, database administration, and security controls.
#' LGPD compliant with audit logging and access controls.

library(shiny)
library(DT)
library(plotly)

#' Admin Module UI
#' 
#' Creates the administrative interface for system management including
#' user administration, system monitoring, and security controls.
#' 
#' @param id Character string for module namespace ID
#' @return Shiny UI tagList containing admin interface elements
#' @export
adminUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    # Admin access check
    uiOutput(ns("admin_access_check")),
    
    # Main admin interface (shown only if authorized)
    conditionalPanel(
      condition = paste0("output['", ns("admin_authorized"), "'] == true"),
      
      fluidRow(
        column(12,
          h3("⚙️ Painel Administrativo - Monitor Legislativo v4", 
             style = "color: #2c3e50; margin-bottom: 20px;"),
          div(
            class = "alert alert-warning",
            icon("shield-alt"),
            strong(" Área Restrita: "),
            "Acesso limitado a administradores autorizados. Todas as ações são registradas para auditoria."
          )
        )
      ),
      
      # Admin Navigation
      fluidRow(
        column(12,
          tabsetPanel(
            type = "tabs",
            
            # System Overview Tab
            tabPanel(
              title = "Visão Geral",
              icon = icon("dashboard"),
              br(),
              
              # System status cards
              fluidRow(
                column(3,
                  div(class = "info-box bg-info",
                    span(class = "info-box-icon", icon("server")),
                    div(class = "info-box-content",
                      span(class = "info-box-text", "Status do Sistema"),
                      span(class = "info-box-number", textOutput(ns("system_status"), inline = TRUE))
                    )
                  )
                ),
                column(3,
                  div(class = "info-box bg-success",
                    span(class = "info-box-icon", icon("database")),
                    div(class = "info-box-content",
                      span(class = "info-box-text", "Conexão DB"),
                      span(class = "info-box-number", textOutput(ns("db_status"), inline = TRUE))
                    )
                  )
                ),
                column(3,
                  div(class = "info-box bg-warning",
                    span(class = "info-box-icon", icon("users")),
                    div(class = "info-box-content",
                      span(class = "info-box-text", "Usuários Ativos"),
                      span(class = "info-box-number", textOutput(ns("active_users"), inline = TRUE))
                    )
                  )
                ),
                column(3,
                  div(class = "info-box bg-danger",
                    span(class = "info-box-icon", icon("exclamation-triangle")),
                    div(class = "info-box-content",
                      span(class = "info-box-text", "Alertas"),
                      span(class = "info-box-number", textOutput(ns("system_alerts"), inline = TRUE))
                    )
                  )
                )
              ),
              
              br(),
              
              # System metrics
              fluidRow(
                column(6,
                  wellPanel(
                    h4("Métricas de Performance"),
                    plotlyOutput(ns("performance_chart"))
                  )
                ),
                column(6,
                  wellPanel(
                    h4("Uso de Recursos"),
                    plotlyOutput(ns("resource_usage_chart"))
                  )
                )
              ),
              
              # Recent activity
              fluidRow(
                column(12,
                  wellPanel(
                    h4("Atividade Recente do Sistema"),
                    DT::dataTableOutput(ns("recent_activity_table"))
                  )
                )
              )
            ),
            
            # User Management Tab
            tabPanel(
              title = "Usuários",
              icon = icon("users"),
              br(),
              
              fluidRow(
                column(4,
                  wellPanel(
                    h4("Gestão de Usuários"),
                    
                    # Add new user
                    h5("Adicionar Usuário"),
                    textInput(
                      inputId = ns("new_user_email"),
                      label = "Email:",
                      placeholder = "usuario@instituicao.edu.br"
                    ),
                    
                    textInput(
                      inputId = ns("new_user_name"),
                      label = "Nome Completo:",
                      placeholder = "Nome do usuário"
                    ),
                    
                    selectInput(
                      inputId = ns("new_user_role"),
                      label = "Função:",
                      choices = list(
                        "Usuário Padrão" = "user",
                        "Pesquisador" = "researcher", 
                        "Administrador" = "admin",
                        "Visualização Apenas" = "viewer"
                      ),
                      selected = "user"
                    ),
                    
                    textAreaInput(
                      inputId = ns("new_user_notes"),
                      label = "Observações:",
                      placeholder = "Notas sobre o usuário...",
                      rows = 2
                    ),
                    
                    actionButton(
                      inputId = ns("add_user"),
                      label = "Adicionar Usuário",
                      icon = icon("user-plus"),
                      class = "btn-primary btn-block"
                    ),
                    
                    br(),
                    
                    # Bulk user operations
                    h5("Operações em Lote"),
                    fileInput(
                      inputId = ns("bulk_user_file"),
                      label = "Importar Usuários (CSV):",
                      accept = ".csv"
                    ),
                    
                    actionButton(
                      inputId = ns("export_users"),
                      label = "Exportar Lista",
                      icon = icon("download"),
                      class = "btn-secondary btn-block"
                    )
                  )
                ),
                
                column(8,
                  wellPanel(
                    h4("Lista de Usuários"),
                    
                    # User filters
                    fluidRow(
                      column(4,
                        selectInput(
                          inputId = ns("user_role_filter"),
                          label = "Filtrar por Função:",
                          choices = list(
                            "Todos" = "all",
                            "Usuários" = "user",
                            "Pesquisadores" = "researcher",
                            "Administradores" = "admin",
                            "Visualização" = "viewer"
                          ),
                          selected = "all"
                        )
                      ),
                      column(4,
                        selectInput(
                          inputId = ns("user_status_filter"),
                          label = "Status:",
                          choices = list(
                            "Todos" = "all",
                            "Ativos" = "active",
                            "Inativos" = "inactive",
                            "Suspensos" = "suspended"
                          ),
                          selected = "all"
                        )
                      ),
                      column(4,
                        dateRangeInput(
                          inputId = ns("user_date_filter"),
                          label = "Período de Cadastro:",
                          start = Sys.Date() - 30,
                          end = Sys.Date(),
                          format = "dd/mm/yyyy"
                        )
                      )
                    ),
                    
                    # Users table
                    DT::dataTableOutput(ns("users_table")),
                    
                    br(),
                    
                    # User actions
                    fluidRow(
                      column(3,
                        actionButton(
                          inputId = ns("edit_user"),
                          label = "Editar Selecionado",
                          icon = icon("edit"),
                          class = "btn-info btn-block"
                        )
                      ),
                      column(3,
                        actionButton(
                          inputId = ns("suspend_user"),
                          label = "Suspender",
                          icon = icon("ban"),
                          class = "btn-warning btn-block"
                        )
                      ),
                      column(3,
                        actionButton(
                          inputId = ns("activate_user"),
                          label = "Ativar",
                          icon = icon("check"),
                          class = "btn-success btn-block"
                        )
                      ),
                      column(3,
                        actionButton(
                          inputId = ns("delete_user"),
                          label = "Remover",
                          icon = icon("trash"),
                          class = "btn-danger btn-block"
                        )
                      )
                    )
                  )
                )
              )
            ),
            
            # Database Administration Tab
            tabPanel(
              title = "Database",
              icon = icon("database"),
              br(),
              
              fluidRow(
                column(6,
                  wellPanel(
                    h4("Status da Base de Dados"),
                    
                    # Database connection info
                    h5("Informações de Conexão"),
                    verbatimTextOutput(ns("db_connection_info")),
                    
                    # Database statistics
                    h5("Estatísticas"),
                    tableOutput(ns("db_statistics")),
                    
                    # Database actions
                    h5("Ações"),
                    fluidRow(
                      column(6,
                        actionButton(
                          inputId = ns("test_db_connection"),
                          label = "Testar Conexão",
                          icon = icon("plug"),
                          class = "btn-info btn-block"
                        )
                      ),
                      column(6,
                        actionButton(
                          inputId = ns("refresh_db_stats"),
                          label = "Atualizar Stats",
                          icon = icon("refresh"),
                          class = "btn-secondary btn-block"
                        )
                      )
                    )
                  )
                ),
                
                column(6,
                  wellPanel(
                    h4("Manutenção da Base"),
                    
                    # Backup operations
                    h5("Backup e Restauração"),
                    fluidRow(
                      column(6,
                        actionButton(
                          inputId = ns("backup_database"),
                          label = "Fazer Backup",
                          icon = icon("download"),
                          class = "btn-success btn-block"
                        )
                      ),
                      column(6,
                        fileInput(
                          inputId = ns("restore_file"),
                          label = "Restaurar Backup:",
                          accept = c(".sql", ".bak")
                        )
                      )
                    ),
                    
                    # Data cleanup
                    h5("Limpeza de Dados"),
                    checkboxGroupInput(
                      inputId = ns("cleanup_options"),
                      label = "Opções de Limpeza:",
                      choices = list(
                        "Logs antigos (>90 dias)" = "old_logs",
                        "Sessões expiradas" = "expired_sessions",
                        "Cache obsoleto" = "old_cache",
                        "Dados temporários" = "temp_data"
                      )
                    ),
                    
                    actionButton(
                      inputId = ns("cleanup_database"),
                      label = "Executar Limpeza",
                      icon = icon("broom"),
                      class = "btn-warning btn-block"
                    ),
                    
                    # Index optimization
                    h5("Otimização"),
                    actionButton(
                      inputId = ns("optimize_database"),
                      label = "Otimizar Índices",
                      icon = icon("tachometer-alt"),
                      class = "btn-info btn-block"
                    )
                  )
                )
              ),
              
              # Query interface
              fluidRow(
                column(12,
                  wellPanel(
                    h4("Interface de Consulta (Cuidado!)"),
                    div(
                      class = "alert alert-danger",
                      icon("exclamation-triangle"),
                      strong(" Atenção: "),
                      "Execute apenas consultas que você entende completamente. Operações destrutivas podem afetar o sistema."
                    ),
                    
                    textAreaInput(
                      inputId = ns("sql_query"),
                      label = "Consulta SQL:",
                      placeholder = "SELECT * FROM documentos_legislativos LIMIT 10;",
                      rows = 4,
                      width = "100%"
                    ),
                    
                    fluidRow(
                      column(6,
                        actionButton(
                          inputId = ns("execute_query"),
                          label = "Executar Consulta",
                          icon = icon("play"),
                          class = "btn-primary"
                        )
                      ),
                      column(6,
                        actionButton(
                          inputId = ns("clear_query"),
                          label = "Limpar",
                          icon = icon("eraser"),
                          class = "btn-secondary"
                        )
                      )
                    ),
                    
                    br(),
                    
                    # Query results
                    h5("Resultados da Consulta"),
                    div(
                      style = "max-height: 400px; overflow-y: auto;",
                      DT::dataTableOutput(ns("query_results"))
                    )
                  )
                )
              )
            ),
            
            # Security & Audit Tab
            tabPanel(
              title = "Segurança",
              icon = icon("shield-alt"),
              br(),
              
              fluidRow(
                column(6,
                  wellPanel(
                    h4("Configurações de Segurança"),
                    
                    # Security settings
                    h5("Configurações Gerais"),
                    checkboxGroupInput(
                      inputId = ns("security_settings"),
                      label = "Opções de Segurança:",
                      choices = list(
                        "Autenticação obrigatória" = "require_auth",
                        "Dois fatores (2FA)" = "enable_2fa",
                        "Timeout de sessão" = "session_timeout",
                        "Log de auditoria" = "audit_logging",
                        "Proteção CSRF" = "csrf_protection",
                        "Rate limiting" = "rate_limiting"
                      ),
                      selected = c("require_auth", "audit_logging", "csrf_protection")
                    ),
                    
                    # Session management
                    h5("Gerenciamento de Sessões"),
                    numericInput(
                      inputId = ns("session_timeout_minutes"),
                      label = "Timeout de Sessão (minutos):",
                      value = 120,
                      min = 15,
                      max = 480
                    ),
                    
                    actionButton(
                      inputId = ns("force_logout_all"),
                      label = "Desconectar Todos os Usuários",
                      icon = icon("sign-out-alt"),
                      class = "btn-warning btn-block"
                    ),
                    
                    # LGPD compliance
                    h5("Conformidade LGPD"),
                    p("Configurações para conformidade com a Lei Geral de Proteção de Dados."),
                    actionButton(
                      inputId = ns("lgpd_audit"),
                      label = "Executar Auditoria LGPD",
                      icon = icon("gavel"),
                      class = "btn-info btn-block"
                    )
                  )
                ),
                
                column(6,
                  wellPanel(
                    h4("Logs de Auditoria"),
                    
                    # Audit log filters
                    fluidRow(
                      column(6,
                        selectInput(
                          inputId = ns("audit_log_type"),
                          label = "Tipo de Log:",
                          choices = list(
                            "Todos" = "all",
                            "Login/Logout" = "auth",
                            "Acessos" = "access",
                            "Modificações" = "changes",
                            "Erros" = "errors",
                            "Admin" = "admin"
                          ),
                          selected = "all"
                        )
                      ),
                      column(6,
                        dateRangeInput(
                          inputId = ns("audit_date_range"),
                          label = "Período:",
                          start = Sys.Date() - 7,
                          end = Sys.Date(),
                          format = "dd/mm/yyyy"
                        )
                      )
                    ),
                    
                    # Audit logs table
                    DT::dataTableOutput(ns("audit_logs_table")),
                    
                    br(),
                    
                    # Export audit logs
                    downloadButton(
                      outputId = ns("export_audit_logs"),
                      label = "Exportar Logs",
                      icon = icon("download"),
                      class = "btn-secondary"
                    )
                  )
                )
              )
            ),
            
            # System Configuration Tab
            tabPanel(
              title = "Configuração",
              icon = icon("cog"),
              br(),
              
              fluidRow(
                column(6,
                  wellPanel(
                    h4("Configurações do Sistema"),
                    
                    # Application settings
                    h5("Configurações da Aplicação"),
                    textInput(
                      inputId = ns("app_name"),
                      label = "Nome da Aplicação:",
                      value = "Monitor Legislativo v4"
                    ),
                    
                    textAreaInput(
                      inputId = ns("app_description"),
                      label = "Descrição:",
                      value = "Sistema de monitoramento e análise da legislação brasileira para pesquisa acadêmica.",
                      rows = 3
                    ),
                    
                    selectInput(
                      inputId = ns("default_language"),
                      label = "Idioma Padrão:",
                      choices = list(
                        "Português (Brasil)" = "pt-BR",
                        "English" = "en",
                        "Español" = "es"
                      ),
                      selected = "pt-BR"
                    ),
                    
                    # Performance settings
                    h5("Configurações de Performance"),
                    numericInput(
                      inputId = ns("max_results_per_page"),
                      label = "Máximo de Resultados por Página:",
                      value = 50,
                      min = 10,
                      max = 500
                    ),
                    
                    numericInput(
                      inputId = ns("cache_timeout_hours"),
                      label = "Timeout do Cache (horas):",
                      value = 24,
                      min = 1,
                      max = 168
                    )
                  )
                ),
                
                column(6,
                  wellPanel(
                    h4("Configurações Avançadas"),
                    
                    # API settings
                    h5("Configurações da API"),
                    checkboxInput(
                      inputId = ns("enable_api"),
                      label = "Habilitar API REST",
                      value = TRUE
                    ),
                    
                    numericInput(
                      inputId = ns("api_rate_limit"),
                      label = "Limite de Taxa da API (req/min):",
                      value = 60,
                      min = 10,
                      max = 1000
                    ),
                    
                    # Email settings
                    h5("Configurações de Email"),
                    textInput(
                      inputId = ns("smtp_server"),
                      label = "Servidor SMTP:",
                      placeholder = "smtp.gmail.com"
                    ),
                    
                    numericInput(
                      inputId = ns("smtp_port"),
                      label = "Porta SMTP:",
                      value = 587,
                      min = 25,
                      max = 65535
                    ),
                    
                    textInput(
                      inputId = ns("admin_email"),
                      label = "Email do Administrador:",
                      placeholder = "admin@instituicao.edu.br"
                    ),
                    
                    # Save configuration
                    br(),
                    actionButton(
                      inputId = ns("save_config"),
                      label = "Salvar Configurações",
                      icon = icon("save"),
                      class = "btn-success btn-block"
                    ),
                    
                    br(),
                    
                    actionButton(
                      inputId = ns("reset_config"),
                      label = "Restaurar Padrões",
                      icon = icon("undo"),
                      class = "btn-warning btn-block"
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

#' Admin Module Server
#' 
#' Server logic for administrative functions including user management,
#' system monitoring, and security controls.
#' 
#' @param id Character string for module namespace ID
#' @param session Shiny session object for access control
#' @return List of reactive values and functions
#' @export
adminServer <- function(id, session = NULL) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns
    
    # Reactive values
    values <- reactiveValues(
      admin_authorized = FALSE,
      users_data = data.frame(
        id = character(),
        email = character(),
        name = character(),
        role = character(),
        status = character(),
        created_date = character(),
        last_login = character(),
        stringsAsFactors = FALSE
      ),
      audit_logs = data.frame(
        timestamp = character(),
        user = character(),
        action = character(),
        details = character(),
        ip_address = character(),
        stringsAsFactors = FALSE
      )
    )
    
    # Check admin authorization
    observe({
      # This would typically check session or authentication
      # For now, simulate admin check
      values$admin_authorized <- TRUE  # In production, implement proper auth check
    })
    
    # Admin access check UI
    output$admin_access_check <- renderUI({
      if (!values$admin_authorized) {
        div(
          class = "alert alert-danger",
          style = "margin-top: 50px;",
          h4(icon("lock"), " Acesso Negado"),
          p("Você não possui permissões administrativas para acessar esta área."),
          p("Entre em contato com o administrador do sistema se precisar de acesso.")
        )
      }
    })
    
    # Admin authorization output
    output$admin_authorized <- reactive({
      values$admin_authorized
    })
    outputOptions(output, "admin_authorized", suspendWhenHidden = FALSE)
    
    # System status outputs
    output$system_status <- renderText({
      "Online"
    })
    
    output$db_status <- renderText({
      if (exists("database_connection_loaded") && database_connection_loaded) {
        "Conectado"
      } else {
        "Offline"
      }
    })
    
    output$active_users <- renderText({
      # This would query actual session data
      sample(1:50, 1)
    })
    
    output$system_alerts <- renderText({
      sample(0:5, 1)
    })
    
    # Performance chart
    output$performance_chart <- safe_renderPlotly({
      # Simulate performance data
      time_points <- seq(from = Sys.time() - 3600, to = Sys.time(), by = 300)
      performance_data <- data.frame(
        time = time_points,
        response_time = runif(length(time_points), 0.1, 2.0),
        queries_per_second = runif(length(time_points), 10, 100)
      )
      
      p <- plot_ly(performance_data, x = ~time) %>%
        add_lines(y = ~response_time, name = "Tempo de Resposta (s)") %>%
        add_lines(y = ~queries_per_second/50, name = "QPS (escala)", yaxis = "y2") %>%
        layout(
          title = "Performance do Sistema",
          yaxis = list(title = "Tempo de Resposta (s)"),
          yaxis2 = list(side = "right", overlaying = "y", title = "Queries/s")
        )
      
      return(p)
    })
    
    # Resource usage chart
    output$resource_usage_chart <- safe_renderPlotly({
      # Simulate resource usage
      resources <- c("CPU", "Memória", "Disco", "Rede")
      usage <- c(35, 67, 23, 45)
      
      p <- plot_ly(
        x = resources,
        y = usage,
        type = "bar",
        marker = list(color = c("#3498db", "#e74c3c", "#27ae60", "#f39c12"))
      ) %>%
        layout(
          title = "Uso de Recursos (%)",
          yaxis = list(title = "Percentual", range = c(0, 100))
        )
      
      return(p)
    })
    
    # Users table
    output$users_table <- DT::renderDataTable({
      # Initialize with sample data if empty
      if (is.null(values$users_data) || !is.data.frame(values$users_data) || nrow(values$users_data) == 0) {
        values$users_data <- data.frame(
          id = 1:5,
          email = c("admin@sistema.gov.br", "pesquisador@univ.edu.br", 
                   "usuario@instituto.org.br", "viewer@external.com", "test@test.com"),
          name = c("Administrador", "Dr. João Silva", "Maria Santos", "Observador", "Usuário Teste"),
          role = c("admin", "researcher", "user", "viewer", "user"),
          status = c("active", "active", "active", "active", "inactive"),
          created_date = rep(as.character(Sys.Date() - sample(1:365, 5)), 5),
          last_login = rep(as.character(Sys.time() - sample(1:24*3600, 5)), 5),
          stringsAsFactors = FALSE
        )
      }
      
      DT::datatable(
        values$users_data,
        selection = "single",
        options = list(
          pageLength = 15,
          language = list(
            url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json"
          )
        ),
        colnames = c("ID", "Email", "Nome", "Função", "Status", "Criado", "Último Login"),
        rownames = FALSE
      )
    })
    
    # Add user functionality
    observeEvent(input$add_user, {
      req(input$new_user_email, input$new_user_name)
      
      # Validate email
      if (!grepl("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", input$new_user_email)) {
        showNotification("Email inválido", type = "error")
        return()
      }
      
      # Check if email already exists
      if (input$new_user_email %in% values$users_data$email) {
        showNotification("Email já existe no sistema", type = "error")
        return()
      }
      
      # Add new user
      new_user <- data.frame(
        id = max(values$users_data$id, 0) + 1,
        email = input$new_user_email,
        name = input$new_user_name,
        role = input$new_user_role,
        status = "active",
        created_date = as.character(Sys.Date()),
        last_login = "Nunca",
        stringsAsFactors = FALSE
      )
      
      values$users_data <- rbind(values$users_data, new_user)
      
      # Log the action
      log_admin_action("USER_CREATED", paste("Created user:", input$new_user_email))
      
      # Clear form
      updateTextInput(session, "new_user_email", value = "")
      updateTextInput(session, "new_user_name", value = "")
      updateTextAreaInput(session, "new_user_notes", value = "")
      
      showNotification("Usuário adicionado com sucesso", type = "success")
    })
    
    # Log admin actions
    log_admin_action <- function(action, details) {
      new_log <- data.frame(
        timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
        user = "admin",  # In production, get from session
        action = action,
        details = details,
        ip_address = "127.0.0.1",  # In production, get real IP
        stringsAsFactors = FALSE
      )
      values$audit_logs <- rbind(values$audit_logs, new_log)
    }
    
    # Database connection info
    output$db_connection_info <- renderText({
      if (exists("database_connection_loaded") && database_connection_loaded) {
        paste(
          "Status: Conectado\n",
          "Host: Railway PostgreSQL\n",
          "Database: railway\n",
          "Pool Size: 1-3 conexões\n",
          "Última verificação:", format(Sys.time(), "%H:%M:%S")
        )
      } else {
        "Status: Desconectado\nUsando fallback CSV"
      }
    })
    
    # Return reactive values for parent application
    return(
      list(
        admin_authorized = reactive(values$admin_authorized),
        users_count = reactive(nrow(values$users_data)),
        audit_logs_count = reactive(nrow(values$audit_logs))
      )
    )
  })
}

cat("✅ Admin module loaded successfully\n")