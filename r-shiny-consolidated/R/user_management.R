# User Management System for Monitor Legislativo v4
# User profiles, role management, and administrative functions

library(shiny)
library(htmltools)
library(DT)
library(dplyr)
library(shinycssloaders)
library(lubridate)
library(jsonlite)

# User management configuration
USER_MGMT_CONFIG <- list(
  profile_fields = list(
    "name" = list(label = "Nome Completo", type = "text", required = TRUE),
    "email" = list(label = "Email", type = "email", required = TRUE, readonly = TRUE),
    "institution" = list(label = "Instituição", type = "text", required = FALSE),
    "department" = list(label = "Departamento", type = "text", required = FALSE),
    "position" = list(label = "Cargo", type = "text", required = FALSE),
    "phone" = list(label = "Telefone", type = "tel", required = FALSE),
    "bio" = list(label = "Biografia", type = "textarea", required = FALSE),
    "research_interests" = list(label = "Interesses de Pesquisa", type = "textarea", required = FALSE),
    "orcid" = list(label = "ORCID iD", type = "url", required = FALSE),
    "lattes" = list(label = "Currículo Lattes", type = "url", required = FALSE)
  ),
  
  preference_categories = list(
    "interface" = list(
      label = "Interface",
      settings = list(
        "theme" = list(label = "Tema", type = "select", options = c("Claro" = "light", "Escuro" = "dark", "Auto" = "auto"), default = "light"),
        "language" = list(label = "Idioma", type = "select", options = c("Português" = "pt", "English" = "en"), default = "pt"),
        "compact_mode" = list(label = "Modo Compacto", type = "checkbox", default = FALSE),
        "animations" = list(label = "Animações", type = "checkbox", default = TRUE)
      )
    ),
    "notifications" = list(
      label = "Notificações",
      settings = list(
        "email_notifications" = list(label = "Notificações por Email", type = "checkbox", default = TRUE),
        "system_alerts" = list(label = "Alertas do Sistema", type = "checkbox", default = TRUE),
        "research_updates" = list(label = "Atualizações de Pesquisa", type = "checkbox", default = FALSE),
        "weekly_digest" = list(label = "Resumo Semanal", type = "checkbox", default = FALSE)
      )
    ),
    "data" = list(
      label = "Dados",
      settings = list(
        "auto_save" = list(label = "Salvamento Automático", type = "checkbox", default = TRUE),
        "default_export_format" = list(label = "Formato de Exportação Padrão", type = "select", 
                                     options = c("CSV" = "csv", "Excel" = "xlsx", "JSON" = "json"), default = "csv"),
        "cache_duration" = list(label = "Duração do Cache (horas)", type = "number", min = 1, max = 24, default = 4),
        "max_results" = list(label = "Máximo de Resultados", type = "number", min = 100, max = 5000, default = 1000)
      )
    ),
    "privacy" = list(
      label = "Privacidade",
      settings = list(
        "profile_visibility" = list(label = "Visibilidade do Perfil", type = "select", 
                                  options = c("Público" = "public", "Institucional" = "institutional", "Privado" = "private"), 
                                  default = "institutional"),
        "activity_tracking" = list(label = "Rastreamento de Atividade", type = "checkbox", default = TRUE),
        "analytics_participation" = list(label = "Participar de Análises", type = "checkbox", default = FALSE),
        "data_retention" = list(label = "Retenção de Dados (dias)", type = "number", min = 30, max = 365, default = 90)
      )
    )
  ),
  
  admin_permissions = c("manage_users", "system_config", "view_audit", "manage_roles", "system_maintenance"),
  
  user_status_options = c("active", "inactive", "suspended", "pending_verification"),
  
  bulk_actions = list(
    "activate" = "Ativar Usuários",
    "deactivate" = "Desativar Usuários", 
    "change_role" = "Alterar Função",
    "send_notification" = "Enviar Notificação",
    "export_data" = "Exportar Dados"
  )
)

#' Create user profile interface
#' @param id Module ID
#' @return User profile UI
user_profile_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "user-profile-container",
    
    # Profile header
    div(
      class = "profile-header",
      style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 12px 12px 0 0; color: white;",
      
      fluidRow(
        column(8,
          h3("👤 Perfil do Usuário", style = "margin: 0; text-shadow: 0 1px 2px rgba(0,0,0,0.3);"),
          p("Gerencie suas informações pessoais e preferências", 
            style = "margin: 5px 0 0 0; opacity: 0.9; font-size: 0.95em;")
        ),
        
        column(4,
          div(
            class = "profile-actions text-end",
            
            actionButton(
              ns("save_profile"),
              "💾 Salvar",
              class = "btn btn-light btn-sm me-2"
            ),
            
            actionButton(
              ns("cancel_changes"),
              "🚫 Cancelar",
              class = "btn btn-outline-light btn-sm"
            )
          )
        )
      )
    ),
    
    # Profile content tabs
    div(
      class = "profile-content",
      style = "background: white;",
      
      navset_card_tab(
        id = ns("profile_tabs"),
        
        # Personal information tab
        nav_panel(
          "📋 Informações Pessoais",
          
          fluidRow(
            column(4,
              # Profile picture section
              div(
                class = "profile-picture-section text-center mb-4",
                style = "padding: 20px;",
                
                div(
                  class = "profile-picture-container",
                  style = "margin-bottom: 15px;",
                  
                  div(
                    id = ns("profile_picture"),
                    style = "width: 120px; height: 120px; border-radius: 50%; margin: 0 auto; background: #f8f9fa; border: 3px solid #e9ecef; display: flex; align-items: center; justify-content: center;",
                    
                    uiOutput(ns("profile_picture_display"))
                  )
                ),
                
                fileInput(
                  ns("upload_picture"),
                  NULL,
                  accept = c(".jpg", ".jpeg", ".png"),
                  buttonLabel = "📸 Alterar Foto",
                  multiple = FALSE
                ),
                
                div(
                  class = "profile-stats mt-3",
                  style = "background: #f8f9fa; padding: 15px; border-radius: 8px;",
                  
                  div(
                    class = "stat-item mb-2",
                    strong("Função: "), 
                    span(textOutput(ns("user_role"), inline = TRUE), class = "badge bg-primary")
                  ),
                  
                  div(
                    class = "stat-item mb-2",
                    strong("Instituição: "), 
                    textOutput(ns("user_institution"), inline = TRUE)
                  ),
                  
                  div(
                    class = "stat-item mb-2",
                    strong("Último acesso: "), 
                    textOutput(ns("last_login"), inline = TRUE)
                  ),
                  
                  div(
                    class = "stat-item",
                    strong("Membro desde: "), 
                    textOutput(ns("member_since"), inline = TRUE)
                  )
                )
              )
            ),
            
            column(8,
              # Profile form
              div(
                class = "profile-form",
                
                h5("📝 Informações Básicas", class = "mb-3"),
                
                # Dynamic form fields
                uiOutput(ns("profile_form_fields")),
                
                hr(),
                
                h5("🎓 Informações Acadêmicas", class = "mb-3"),
                
                fluidRow(
                  column(6,
                    textInput(
                      ns("orcid"),
                      "ORCID iD:",
                      placeholder = "https://orcid.org/0000-0000-0000-0000"
                    )
                  ),
                  
                  column(6,
                    textInput(
                      ns("lattes"),
                      "Currículo Lattes:",
                      placeholder = "http://lattes.cnpq.br/..."
                    )
                  )
                ),
                
                textAreaInput(
                  ns("research_interests"),
                  "Interesses de Pesquisa:",
                  rows = 3,
                  placeholder = "Descreva suas áreas de interesse em pesquisa..."
                ),
                
                textAreaInput(
                  ns("bio"),
                  "Biografia:",
                  rows = 4,
                  placeholder = "Conte um pouco sobre você e sua experiência..."
                )
              )
            )
          )
        ),
        
        # Preferences tab
        nav_panel(
          "⚙️ Preferências",
          
          # Dynamic preferences sections
          uiOutput(ns("preferences_sections"))
        ),
        
        # Activity tab
        nav_panel(
          "📊 Atividade",
          
          fluidRow(
            column(6,
              card(
                card_header("📈 Estatísticas de Uso"),
                card_body(
                  htmlOutput(ns("activity_stats"))
                )
              )
            ),
            
            column(6,
              card(
                card_header("🕐 Atividade Recente"),
                card_body(
                  style = "max-height: 300px; overflow-y: auto;",
                  htmlOutput(ns("recent_activity"))
                )
              )
            )
          ),
          
          br(),
          
          fluidRow(
            column(12,
              card(
                card_header("📋 Histórico de Sessões"),
                card_body(
                  withSpinner(
                    DT::dataTableOutput(ns("session_history")),
                    type = 4
                  )
                )
              )
            )
          )
        ),
        
        # Security tab
        nav_panel(
          "🔐 Segurança",
          
          fluidRow(
            column(6,
              card(
                card_header("🔑 Autenticação"),
                card_body(
                  div(
                    class = "security-info",
                    
                    div(
                      class = "security-item mb-3",
                      h6("Método de Login"),
                      p(textOutput(ns("auth_method"), inline = TRUE), class = "text-muted")
                    ),
                    
                    div(
                      class = "security-item mb-3",
                      h6("Sessões Ativas"),
                      p(paste(textOutput(ns("active_sessions"), inline = TRUE), "sessões ativas"), class = "text-muted")
                    ),
                    
                    actionButton(
                      ns("revoke_all_sessions"),
                      "🚫 Revogar Todas as Sessões",
                      class = "btn btn-warning w-100"
                    )
                  )
                )
              )
            ),
            
            column(6,
              card(
                card_header("🛡️ Privacidade"),
                card_body(
                  div(
                    class = "privacy-controls",
                    
                    checkboxInput(
                      ns("two_factor_enabled"),
                      "Ativar autenticação de dois fatores",
                      value = FALSE
                    ),
                    
                    checkboxInput(
                      ns("activity_logging"),
                      "Permitir registro de atividades",
                      value = TRUE
                    ),
                    
                    checkboxInput(
                      ns("data_sharing"),
                      "Permitir compartilhamento de dados para pesquisa",
                      value = FALSE
                    ),
                    
                    hr(),
                    
                    h6("🗑️ Gerenciar Dados"),
                    
                    actionButton(
                      ns("export_data"),
                      "📤 Exportar Meus Dados",
                      class = "btn btn-outline-primary w-100 mb-2"
                    ),
                    
                    actionButton(
                      ns("delete_account"),
                      "🗑️ Excluir Conta",
                      class = "btn btn-outline-danger w-100"
                    )
                  )
                )
              )
            )
          )
        )
      )
    ),
    
    # Profile footer
    div(
      class = "profile-footer",
      style = "background: #f8f9fa; padding: 15px; border-top: 1px solid #dee2e6; border-radius: 0 0 12px 12px;",
      
      fluidRow(
        column(8,
          div(
            class = "d-flex align-items-center",
            span("📝 Última atualização: ", class = "text-muted me-2"),
            strong(textOutput(ns("profile_updated"), inline = TRUE), class = "text-primary")
          )
        ),
        
        column(4,
          div(
            class = "text-end",
            span("✅ Todas as alterações foram salvas", class = "text-success", style = "display: none;", id = ns("save_status"))
          )
        )
      )
    )
  )
}

#' Create user management interface (admin)
#' @param id Module ID
#' @return User management UI
user_management_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "user-management-container",
    
    # Management header
    div(
      class = "management-header",
      style = "background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); padding: 20px; border-radius: 12px 12px 0 0; color: white;",
      
      fluidRow(
        column(8,
          h3("👥 Gerenciamento de Usuários", style = "margin: 0; text-shadow: 0 1px 2px rgba(0,0,0,0.3);"),
          p("Administre usuários, funções e permissões do sistema", 
            style = "margin: 5px 0 0 0; opacity: 0.9; font-size: 0.95em;")
        ),
        
        column(4,
          div(
            class = "management-actions text-end",
            
            actionButton(
              ns("add_user"),
              "➕ Adicionar Usuário",
              class = "btn btn-light btn-sm me-2"
            ),
            
            actionButton(
              ns("export_users"),
              "📤 Exportar",
              class = "btn btn-outline-light btn-sm"
            )
          )
        )
      )
    ),
    
    # Management content
    div(
      class = "management-content",
      style = "background: white;",
      
      navset_card_tab(
        id = ns("management_tabs"),
        
        # Users list tab
        nav_panel(
          "👤 Usuários",
          
          # Filters and controls
          div(
            class = "users-controls",
            style = "background: #f8f9fa; padding: 15px; border-bottom: 1px solid #dee2e6;",
            
            fluidRow(
              column(3,
                selectInput(
                  ns("filter_role"),
                  "Filtrar por Função:",
                  choices = c("Todas" = "", names(AUTH_CONFIG$user_roles)),
                  width = "100%"
                )
              ),
              
              column(3,
                selectInput(
                  ns("filter_status"),
                  "Filtrar por Status:",
                  choices = c("Todos" = "", "Ativo" = "active", "Inativo" = "inactive", "Suspenso" = "suspended"),
                  width = "100%"
                )
              ),
              
              column(3,
                textInput(
                  ns("search_users"),
                  "Buscar:",
                  placeholder = "Nome, email ou instituição...",
                  width = "100%"
                )
              ),
              
              column(3,
                br(),
                actionButton(
                  ns("refresh_users"),
                  "🔄 Atualizar",
                  class = "btn btn-outline-primary w-100"
                )
              )
            )
          ),
          
          # Bulk actions
          div(
            class = "bulk-actions",
            style = "padding: 10px 15px; background: white; border-bottom: 1px solid #dee2e6;",
            
            fluidRow(
              column(6,
                div(
                  class = "d-flex align-items-center",
                  checkboxInput(
                    ns("select_all_users"),
                    "Selecionar todos",
                    value = FALSE
                  ),
                  span("(", textOutput(ns("selected_count"), inline = TRUE), " selecionados)", class = "text-muted ms-2")
                )
              ),
              
              column(6,
                div(
                  class = "text-end",
                  
                  conditionalPanel(
                    condition = paste0("output['", ns("has_selection"), "']"),
                    
                    selectInput(
                      ns("bulk_action"),
                      NULL,
                      choices = c("Selecionar ação..." = "", USER_MGMT_CONFIG$bulk_actions),
                      width = "200px"
                    ),
                    
                    actionButton(
                      ns("execute_bulk_action"),
                      "▶️ Executar",
                      class = "btn btn-primary btn-sm"
                    )
                  )
                )
              )
            )
          ),
          
          # Users table
          div(
            class = "users-table",
            
            withSpinner(
              DT::dataTableOutput(ns("users_table")),
              type = 4
            )
          )
        ),
        
        # Roles management tab
        nav_panel(
          "🎭 Funções e Permissões",
          
          fluidRow(
            column(6,
              card(
                card_header("🎭 Funções Disponíveis"),
                card_body(
                  uiOutput(ns("roles_list"))
                )
              )
            ),
            
            column(6,
              card(
                card_header("🔐 Permissões"),
                card_body(
                  uiOutput(ns("permissions_matrix"))
                )
              )
            )
          ),
          
          br(),
          
          fluidRow(
            column(12,
              card(
                card_header("➕ Criar Nova Função"),
                card_body(
                  fluidRow(
                    column(4,
                      textInput(
                        ns("new_role_id"),
                        "ID da Função:",
                        placeholder = "role_id"
                      )
                    ),
                    
                    column(4,
                      textInput(
                        ns("new_role_name"),
                        "Nome da Função:",
                        placeholder = "Nome da Função"
                      )
                    ),
                    
                    column(4,
                      br(),
                      actionButton(
                        ns("create_role"),
                        "➕ Criar Função",
                        class = "btn btn-success w-100"
                      )
                    )
                  ),
                  
                  br(),
                  
                  div(
                    class = "permissions-selection",
                    h6("Permissões:"),
                    checkboxGroupInput(
                      ns("new_role_permissions"),
                      NULL,
                      choices = c(
                        "Leitura" = "read",
                        "Escrita" = "write",
                        "Exclusão" = "delete",
                        "Exportar dados" = "export_data",
                        "Análises avançadas" = "advanced_analytics",
                        "Gerenciar usuários" = "manage_users",
                        "Configuração do sistema" = "system_config"
                      ),
                      inline = TRUE
                    )
                  )
                )
              )
            )
          )
        ),
        
        # Audit log tab
        nav_panel(
          "📊 Log de Auditoria",
          
          # Audit filters
          div(
            class = "audit-controls",
            style = "background: #f8f9fa; padding: 15px; border-bottom: 1px solid #dee2e6;",
            
            fluidRow(
              column(3,
                dateRangeInput(
                  ns("audit_date_range"),
                  "Período:",
                  start = Sys.Date() - 7,
                  end = Sys.Date(),
                  format = "dd/mm/yyyy",
                  language = "pt-BR"
                )
              ),
              
              column(3,
                selectInput(
                  ns("audit_user_filter"),
                  "Usuário:",
                  choices = c("Todos" = ""),
                  width = "100%"
                )
              ),
              
              column(3,
                selectInput(
                  ns("audit_action_filter"),
                  "Ação:",
                  choices = c("Todas" = "", "Login" = "login_success", "Logout" = "logout", "Visualização" = "view", "Exportação" = "export"),
                  width = "100%"
                )
              ),
              
              column(3,
                br(),
                actionButton(
                  ns("refresh_audit"),
                  "🔄 Atualizar Log",
                  class = "btn btn-outline-primary w-100"
                )
              )
            )
          ),
          
          # Audit table
          div(
            class = "audit-table",
            
            withSpinner(
              DT::dataTableOutput(ns("audit_table")),
              type = 4
            )
          )
        ),
        
        # System statistics tab
        nav_panel(
          "📈 Estatísticas",
          
          fluidRow(
            column(3,
              div(
                class = "stat-card",
                style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 12px; text-align: center;",
                
                h3(textOutput(ns("total_users"), inline = TRUE), style = "margin: 0; font-weight: bold;"),
                p("Total de Usuários", style = "margin: 5px 0 0 0; opacity: 0.9;")
              )
            ),
            
            column(3,
              div(
                class = "stat-card",
                style = "background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 20px; border-radius: 12px; text-align: center;",
                
                h3(textOutput(ns("active_users"), inline = TRUE), style = "margin: 0; font-weight: bold;"),
                p("Usuários Ativos", style = "margin: 5px 0 0 0; opacity: 0.9;")
              )
            ),
            
            column(3,
              div(
                class = "stat-card",
                style = "background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; padding: 20px; border-radius: 12px; text-align: center;",
                
                h3(textOutput(ns("active_sessions"), inline = TRUE), style = "margin: 0; font-weight: bold;"),
                p("Sessões Ativas", style = "margin: 5px 0 0 0; opacity: 0.9;")
              )
            ),
            
            column(3,
              div(
                class = "stat-card",
                style = "background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); color: #333; padding: 20px; border-radius: 12px; text-align: center;",
                
                h3(textOutput(ns("login_today"), inline = TRUE), style = "margin: 0; font-weight: bold;"),
                p("Logins Hoje", style = "margin: 5px 0 0 0; opacity: 0.7;")
              )
            )
          ),
          
          br(),
          
          fluidRow(
            column(6,
              card(
                card_header("📊 Usuários por Função"),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("users_by_role_chart"), height = "300px"),
                    type = 4
                  )
                )
              )
            ),
            
            column(6,
              card(
                card_header("📈 Atividade por Dia"),
                card_body(
                  withSpinner(
                    echarts4rOutput(ns("daily_activity_chart"), height = "300px"),
                    type = 4
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

#' User profile server function
#' @param id Module ID
#' @param auth_state Authentication state
#' @param auth_db Database connection
user_profile_server <- function(id, auth_state, auth_db) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for profile state
    profile_values <- reactiveValues(
      user_data = NULL,
      preferences = NULL,
      is_modified = FALSE
    )
    
    # Get current user data
    observe({
      auth_info <- auth_state()
      if (auth_info$is_authenticated) {
        con <- auth_db()
        if (!is.null(con)) {
          user_data <- dbGetQuery(con, "SELECT * FROM users WHERE id = ?", params = list(auth_info$user$user_id))
          if (nrow(user_data) > 0) {
            profile_values$user_data <- user_data[1, ]
            
            # Load preferences
            if (!is.null(user_data$preferences[1]) && user_data$preferences[1] != "") {
              profile_values$preferences <- fromJSON(user_data$preferences[1])
            } else {
              profile_values$preferences <- list()
            }
          }
        }
      }
    })
    
    # Profile form fields
    output$profile_form_fields <- renderUI({
      if (is.null(profile_values$user_data)) return(NULL)
      
      user <- profile_values$user_data
      
      tagList(
        fluidRow(
          column(6,
            textInput(
              ns("profile_name"),
              "Nome Completo:",
              value = user$name
            )
          ),
          
          column(6,
            textInput(
              ns("profile_email"),
              "Email:",
              value = user$email,
              readonly = TRUE
            )
          )
        ),
        
        fluidRow(
          column(6,
            textInput(
              ns("profile_institution"),
              "Instituição:",
              value = user$institution %||% ""
            )
          ),
          
          column(6,
            textInput(
              ns("profile_department"),
              "Departamento:",
              placeholder = "Seu departamento ou área"
            )
          )
        ),
        
        fluidRow(
          column(6,
            textInput(
              ns("profile_position"),
              "Cargo:",
              placeholder = "Sua posição ou cargo"
            )
          ),
          
          column(6,
            textInput(
              ns("profile_phone"),
              "Telefone:",
              placeholder = "+55 (11) 99999-9999"
            )
          )
        )
      )
    })
    
    # Preferences sections
    output$preferences_sections <- renderUI({
      pref_sections <- lapply(names(USER_MGMT_CONFIG$preference_categories), function(cat_id) {
        category <- USER_MGMT_CONFIG$preference_categories[[cat_id]]
        
        card(
          card_header(paste(category$label, "Settings")),
          card_body(
            lapply(names(category$settings), function(setting_id) {
              setting <- category$settings[[setting_id]]
              input_id <- paste0("pref_", cat_id, "_", setting_id)
              
              switch(setting$type,
                "checkbox" = checkboxInput(
                  ns(input_id),
                  setting$label,
                  value = profile_values$preferences[[cat_id]][[setting_id]] %||% setting$default
                ),
                "select" = selectInput(
                  ns(input_id),
                  setting$label,
                  choices = setting$options,
                  selected = profile_values$preferences[[cat_id]][[setting_id]] %||% setting$default
                ),
                "number" = numericInput(
                  ns(input_id),
                  setting$label,
                  value = profile_values$preferences[[cat_id]][[setting_id]] %||% setting$default,
                  min = setting$min,
                  max = setting$max
                )
              )
            })
          )
        )
      })
      
      do.call(tagList, pref_sections)
    })
    
    # Profile outputs
    output$profile_picture_display <- renderUI({
      if (!is.null(profile_values$user_data) && !is.null(profile_values$user_data$profile_picture)) {
        tags$img(
          src = profile_values$user_data$profile_picture,
          style = "width: 100%; height: 100%; object-fit: cover; border-radius: 50%;"
        )
      } else {
        icon("user", class = "fa-3x text-muted")
      }
    })
    
    output$user_role <- renderText({
      if (!is.null(profile_values$user_data)) {
        AUTH_CONFIG$user_roles[[profile_values$user_data$role]]$name %||% profile_values$user_data$role
      }
    })
    
    output$user_institution <- renderText({
      if (!is.null(profile_values$user_data)) {
        profile_values$user_data$institution %||% "Não informado"
      }
    })
    
    output$last_login <- renderText({
      if (!is.null(profile_values$user_data) && !is.null(profile_values$user_data$last_login)) {
        format(as.POSIXct(profile_values$user_data$last_login), "%d/%m/%Y %H:%M")
      } else {
        "Nunca"
      }
    })
    
    output$member_since <- renderText({
      if (!is.null(profile_values$user_data) && !is.null(profile_values$user_data$created_at)) {
        format(as.POSIXct(profile_values$user_data$created_at), "%d/%m/%Y")
      }
    })
    
    # Save profile changes
    observeEvent(input$save_profile, {
      auth_info <- auth_state()
      if (auth_info$is_authenticated) {
        con <- auth_db()
        if (!is.null(con)) {
          tryCatch({
            # Update user data
            dbExecute(con, "
              UPDATE users 
              SET name = ?, institution = ?, updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
            ", params = list(
              input$profile_name,
              input$profile_institution,
              auth_info$user$user_id
            ))
            
            # Update preferences
            preferences_data <- list()
            for (cat_id in names(USER_MGMT_CONFIG$preference_categories)) {
              category <- USER_MGMT_CONFIG$preference_categories[[cat_id]]
              for (setting_id in names(category$settings)) {
                input_id <- paste0("pref_", cat_id, "_", setting_id)
                if (!is.null(input[[input_id]])) {
                  if (is.null(preferences_data[[cat_id]])) preferences_data[[cat_id]] <- list()
                  preferences_data[[cat_id]][[setting_id]] <- input[[input_id]]
                }
              }
            }
            
            if (length(preferences_data) > 0) {
              dbExecute(con, "UPDATE users SET preferences = ? WHERE id = ?", 
                       params = list(toJSON(preferences_data), auth_info$user$user_id))
            }
            
            log_audit_event(con, auth_info$user$user_id, "profile_updated", details = "User profile updated")
            
            showNotification("Perfil atualizado com sucesso!", type = "success")
            
          }, error = function(e) {
            log_event(paste("Error updating profile:", e$message), "ERROR")
            showNotification("Erro ao atualizar perfil", type = "error")
          })
        }
      }
    })
  })
}

#' User management server function
#' @param id Module ID
#' @param auth_state Authentication state
#' @param auth_db Database connection
user_management_server <- function(id, auth_state, auth_db) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for management state
    mgmt_values <- reactiveValues(
      users_data = NULL,
      audit_data = NULL,
      selected_users = NULL
    )
    
    # Load users data
    load_users_data <- function() {
      con <- auth_db()
      if (!is.null(con)) {
        tryCatch({
          users_query <- "
            SELECT u.*, 
                   COUNT(s.id) as active_sessions,
                   MAX(s.last_activity) as last_session_activity
            FROM users u
            LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = 1
            GROUP BY u.id
            ORDER BY u.created_at DESC
          "
          
          mgmt_values$users_data <- dbGetQuery(con, users_query)
          
        }, error = function(e) {
          log_event(paste("Error loading users data:", e$message), "ERROR")
        })
      }
    }
    
    # Load audit data
    load_audit_data <- function() {
      con <- auth_db()
      if (!is.null(con)) {
        tryCatch({
          audit_query <- "
            SELECT a.*, u.name as user_name, u.email as user_email
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.timestamp >= ? AND a.timestamp <= ?
            ORDER BY a.timestamp DESC
            LIMIT 1000
          "
          
          date_from <- input$audit_date_range[1] %||% (Sys.Date() - 7)
          date_to <- input$audit_date_range[2] %||% Sys.Date()
          
          mgmt_values$audit_data <- dbGetQuery(con, audit_query, params = list(
            paste(date_from, "00:00:00"),
            paste(date_to, "23:59:59")
          ))
          
        }, error = function(e) {
          log_event(paste("Error loading audit data:", e$message), "ERROR")
        })
      }
    }
    
    # Initialize data loading
    observe({
      load_users_data()
      load_audit_data()
    })
    
    # Refresh data
    observeEvent(input$refresh_users, {
      load_users_data()
    })
    
    observeEvent(input$refresh_audit, {
      load_audit_data()
    })
    
    # Users table
    output$users_table <- DT::renderDataTable({
      if (is.null(mgmt_values$users_data)) return(NULL)
      
      display_data <- mgmt_values$users_data %>%
        mutate(
          status = ifelse(is_active == 1, "Ativo", "Inativo"),
          role_display = sapply(role, function(r) AUTH_CONFIG$user_roles[[r]]$name %||% r),
          created_at = format(as.POSIXct(created_at), "%d/%m/%Y"),
          last_login = ifelse(is.na(last_login), "Nunca", format(as.POSIXct(last_login), "%d/%m/%Y %H:%M"))
        ) %>%
        select(
          ID = id,
          Nome = name,
          Email = email,
          Função = role_display,
          Instituição = institution,
          Status = status,
          `Criado em` = created_at,
          `Último login` = last_login,
          `Sessões ativas` = active_sessions
        )
      
      display_data
      
    }, options = list(
      pageLength = 25,
      scrollX = TRUE,
      language = list(
        url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
      ),
      columnDefs = list(
        list(targets = 0, visible = FALSE)  # Hide ID column
      )
    ), selection = 'multiple')
    
    # Audit table
    output$audit_table <- DT::renderDataTable({
      if (is.null(mgmt_values$audit_data)) return(NULL)
      
      display_data <- mgmt_values$audit_data %>%
        mutate(
          timestamp = format(as.POSIXct(timestamp), "%d/%m/%Y %H:%M:%S")
        ) %>%
        select(
          Usuário = user_name,
          Email = user_email,
          Ação = action,
          Recurso = resource,
          Detalhes = details,
          `Data/Hora` = timestamp,
          IP = ip_address
        )
      
      display_data
      
    }, options = list(
      pageLength = 25,
      scrollX = TRUE,
      language = list(
        url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
      ),
      order = list(list(5, 'desc'))  # Order by timestamp
    ))
    
    # Statistics outputs
    output$total_users <- renderText({
      if (is.null(mgmt_values$users_data)) "0"
      else format(nrow(mgmt_values$users_data), big.mark = ".")
    })
    
    output$active_users <- renderText({
      if (is.null(mgmt_values$users_data)) "0"
      else format(sum(mgmt_values$users_data$is_active == 1, na.rm = TRUE), big.mark = ".")
    })
    
    output$active_sessions <- renderText({
      if (is.null(mgmt_values$users_data)) "0"
      else format(sum(mgmt_values$users_data$active_sessions, na.rm = TRUE), big.mark = ".")
    })
    
    output$login_today <- renderText({
      if (is.null(mgmt_values$users_data)) "0"
      else {
        today_logins <- sum(
          !is.na(mgmt_values$users_data$last_login) & 
          as.Date(mgmt_values$users_data$last_login) == Sys.Date(),
          na.rm = TRUE
        )
        format(today_logins, big.mark = ".")
      }
    })
    
    # Charts
    output$users_by_role_chart <- renderEcharts4r({
      if (is.null(mgmt_values$users_data)) return(NULL)
      
      role_data <- mgmt_values$users_data %>%
        count(role) %>%
        mutate(role_name = sapply(role, function(r) AUTH_CONFIG$user_roles[[r]]$name %||% r))
      
      role_data %>%
        e_charts(role_name) %>%
        e_pie(n, name = "Usuários") %>%
        e_tooltip(trigger = "item") %>%
        e_legend(orient = "vertical", right = 10)
    })
    
    output$daily_activity_chart <- renderEcharts4r({
      if (is.null(mgmt_values$audit_data)) return(NULL)
      
      daily_data <- mgmt_values$audit_data %>%
        mutate(date = as.Date(timestamp)) %>%
        count(date) %>%
        arrange(date) %>%
        tail(14)  # Last 14 days
      
      daily_data %>%
        e_charts(date) %>%
        e_line(n, smooth = TRUE, name = "Atividade") %>%
        e_area(n, opacity = 0.3) %>%
        e_tooltip(trigger = "axis")
    })
  })
}