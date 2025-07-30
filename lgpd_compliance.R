# LGPD Compliance Module for Monitor Legislativo v4
# Brazilian General Data Protection Law (Lei Geral de Proteção de Dados)
# Implements user consent management, data subject rights, and privacy controls

library(shiny)
library(shinydashboard)
library(DT)
library(jsonlite)

# Source authentication system
source("auth_system.R")

#' LGPD Consent Terms (Portuguese)
LGPD_TERMS <- list(
  privacy_policy = "
    <h3>Política de Privacidade - Monitor Legislativo v4</h3>
    <p><strong>Última atualização:</strong> 29 de julho de 2025</p>
    
    <h4>1. Controlador de Dados</h4>
    <p>O Monitor Legislativo v4 é uma plataforma acadêmica mantida pela Universidade Presbiteriana Mackenzie, 
    localizada na Rua da Consolação, 930, São Paulo-SP, que atua como controlador dos dados pessoais 
    coletados através desta plataforma.</p>
    
    <h4>2. Dados Coletados</h4>
    <p>Coletamos os seguintes dados pessoais:</p>
    <ul>
      <li><strong>Dados de identificação:</strong> Nome completo, endereço de e-mail institucional</li>
      <li><strong>Dados de autenticação:</strong> Informações do provedor OAuth (Google/Microsoft)</li>
      <li><strong>Dados de uso:</strong> Histórico de pesquisas, documentos acessados, exportações realizadas</li>
      <li><strong>Dados técnicos:</strong> Endereço IP, navegador, informações de sessão</li>
    </ul>
    
    <h4>3. Finalidades do Tratamento</h4>
    <p>Seus dados são tratados para as seguintes finalidades:</p>
    <ul>
      <li><strong>Acesso ao sistema:</strong> Autenticação e controle de acesso (Art. 7º, I - LGPD)</li>
      <li><strong>Pesquisa acadêmica:</strong> Fornecimento de acesso à base legislativa para fins de estudo (Art. 7º, IV - LGPD)</li>
      <li><strong>Auditoria e segurança:</strong> Monitoramento de uso e prevenção de abusos (Art. 7º, II - LGPD)</li>
      <li><strong>Melhoria da plataforma:</strong> Análise de uso para aprimoramentos técnicos (Art. 10, I - LGPD)</li>
    </ul>
    
    <h4>4. Base Legal</h4>
    <p>O tratamento de dados tem como base legal:</p>
    <ul>
      <li><strong>Consentimento:</strong> Para dados não essenciais e comunicações (Art. 7º, I)</li>
      <li><strong>Interesse legítimo:</strong> Para segurança e funcionamento da plataforma (Art. 7º, IX)</li>
      <li><strong>Exercício regular de direitos:</strong> Para fins de pesquisa acadêmica (Art. 7º, IV)</li>
    </ul>
  ",
  
  data_processing_consent = "
    <h4>Consentimento para Tratamento de Dados</h4>
    <p>Ao marcar esta opção, você consente com:</p>
    <ul>
      <li>O tratamento de seus dados pessoais para as finalidades descritas na Política de Privacidade</li>
      <li>O registro de suas atividades na plataforma para fins de auditoria e segurança</li>
      <li>O armazenamento de seus dados pelo período necessário para as finalidades acadêmicas (máximo 7 anos)</li>
    </ul>
    <p><strong>Este consentimento é necessário para usar a plataforma.</strong></p>
  ",
  
  marketing_consent = "
    <h4>Consentimento para Comunicações</h4>
    <p>Ao marcar esta opção, você consente em receber:</p>
    <ul>
      <li>Atualizações sobre novas funcionalidades da plataforma</li>
      <li>Convites para pesquisas acadêmicas relacionadas</li>
      <li>Informações sobre eventos e publicações sobre legislação</li>
    </ul>
    <p><strong>Este consentimento é opcional e pode ser retirado a qualquer momento.</strong></p>
  ",
  
  user_rights = "
    <h4>Seus Direitos como Titular de Dados (LGPD)</h4>
    <p>Você possui os seguintes direitos sobre seus dados pessoais:</p>
    <ul>
      <li><strong>Acesso:</strong> Obter informações sobre quais dados temos sobre você</li>
      <li><strong>Correção:</strong> Corrigir dados incompletos, inexatos ou desatualizados</li>
      <li><strong>Eliminação:</strong> Solicitar a exclusão de seus dados</li>
      <li><strong>Portabilidade:</strong> Receber seus dados em formato estruturado</li>
      <li><strong>Revogação:</strong> Retirar seu consentimento a qualquer momento</li>
      <li><strong>Informação:</strong> Saber com quem compartilhamos seus dados</li>
    </ul>
    <p>Para exercer esses direitos, use o painel de controle de privacidade ou entre em contato conosco.</p>
  "
)

#' Generate LGPD consent UI
lgpd_consent_ui <- function() {
  div(
    class = "lgpd-consent-modal",
    style = "background: white; padding: 30px; border-radius: 10px; max-width: 800px; margin: 0 auto;",
    
    div(
      class = "text-center mb-4",
      img(src = "mackenzie-logo.png", height = "60px", style = "margin-bottom: 20px;"),
      h2("Bem-vindo ao Monitor Legislativo v4", style = "color: #0d6efd;"),
      p("Plataforma Acadêmica para Monitoramento Legislativo", style = "color: #6c757d;")
    ),
    
    div(
      class = "lgpd-content",
      style = "max-height: 400px; overflow-y: auto; border: 1px solid #dee2e6; padding: 20px; margin-bottom: 20px;",
      HTML(LGPD_TERMS$privacy_policy)
    ),
    
    div(
      class = "consent-options",
      
      div(
        class = "form-check mb-3",
        style = "border: 2px solid #dc3545; padding: 15px; border-radius: 8px; background: #fff5f5;",
        checkboxInput(
          "data_processing_consent",
          label = NULL,
          value = FALSE
        ),
        div(
          style = "margin-left: 25px;",
          HTML(LGPD_TERMS$data_processing_consent)
        )
      ),
      
      div(
        class = "form-check mb-3",
        style = "border: 1px solid #0dcaf0; padding: 15px; border-radius: 8px; background: #f0faff;",
        checkboxInput(
          "marketing_consent",
          label = NULL,
          value = FALSE
        ),
        div(
          style = "margin-left: 25px;",
          HTML(LGPD_TERMS$marketing_consent)
        )
      )
    ),
    
    div(
      class = "consent-actions text-center",
      
      div(
        class = "mb-3",
        HTML(LGPD_TERMS$user_rights)
      ),
      
      div(
        class = "btn-group",
        actionButton(
          "accept_consent",
          "Aceitar e Continuar",
          class = "btn btn-success btn-lg me-3",
          style = "min-width: 180px;"
        ),
        actionButton(
          "reject_consent", 
          "Não Aceitar",
          class = "btn btn-outline-secondary btn-lg",
          style = "min-width: 150px;"
        )
      ),
      
      div(
        class = "mt-3 text-muted small",
        p("Ao continuar, você confirma ter lido e compreendido nossa Política de Privacidade."),
        p("Para dúvidas sobre tratamento de dados, entre em contato: privacidade@mackenzie.br")
      )
    )
  )
}

#' Generate user privacy dashboard UI
privacy_dashboard_ui <- function(user_session) {
  tagList(
    fluidRow(
      box(
        title = "Controle de Privacidade - LGPD",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        tabsetPanel(
          id = "privacy_tabs",
          
          # Data Overview Tab
          tabPanel(
            "Meus Dados",
            value = "data_overview",
            br(),
            
            fluidRow(
              column(
                6,
                h4("Informações da Conta"),
                div(
                  class = "info-card",
                  style = "background: #f8f9fa; padding: 15px; border-radius: 8px;",
                  p(strong("Nome: "), user_session$full_name),
                  p(strong("E-mail: "), user_session$email),
                  p(strong("Instituição: "), user_session$institutional_affiliation %||% "Não informada"),
                  p(strong("Função: "), paste(user_session$roles, collapse = ", ")),
                  p(strong("Última atualização: "), format(Sys.time(), "%d/%m/%Y %H:%M"))
                )
              ),
              
              column(
                6,
                h4("Status de Consentimento"),
                div(
                  class = "consent-status",
                  div(
                    class = if(user_session$data_processing_consent) "alert alert-success" else "alert alert-warning",
                    strong("Processamento de Dados: "),
                    if(user_session$data_processing_consent) "✓ Consentido" else "⚠ Pendente"
                  ),
                  div(
                    class = if(user_session$marketing_consent) "alert alert-info" else "alert alert-secondary",
                    strong("Comunicações: "),
                    if(user_session$marketing_consent) "✓ Consentido" else "✗ Não consentido"
                  )
                )
              )
            ),
            
            br(),
            actionButton(
              "update_consent",
              "Atualizar Consentimentos",
              class = "btn btn-primary"
            )
          ),
          
          # Access History Tab
          tabPanel(
            "Histórico de Acesso",
            value = "access_history",
            br(),
            
            div(
              class = "access-controls mb-3",
              dateRangeInput(
                "access_date_range",
                "Período:",
                start = Sys.Date() - 30,
                end = Sys.Date(),
                language = "pt-BR",
                separator = "até"
              ),
              actionButton(
                "refresh_access_log",
                "Atualizar",
                class = "btn btn-outline-primary btn-sm"
              )
            ),
            
            DT::dataTableOutput("access_history_table")
          ),
          
          # Data Rights Tab
          tabPanel(
            "Direitos do Titular",
            value = "data_rights",
            br(),
            
            div(
              class = "data-rights-options",
              
              div(
                class = "right-option mb-4",
                style = "border: 1px solid #dee2e6; padding: 20px; border-radius: 8px;",
                h5("📋 Solicitar Cópia dos Dados"),
                p("Receba uma cópia completa de todos os dados que temos sobre você em formato JSON."),
                actionButton(
                  "request_data_export",
                  "Solicitar Exportação",
                  class = "btn btn-outline-primary"
                )
              ),
              
              div(
                class = "right-option mb-4",
                style = "border: 1px solid #ffc107; padding: 20px; border-radius: 8px;",
                h5("✏️ Solicitar Correção"),
                p("Solicite correção de dados incorretos ou desatualizados."),
                textAreaInput(
                  "correction_request",
                  "Descreva as correções necessárias:",
                  placeholder = "Ex: Atualizar afiliação institucional para...",
                  height = "100px"
                ),
                actionButton(
                  "submit_correction",
                  "Enviar Solicitação",
                  class = "btn btn-warning"
                )
              ),
              
              div(
                class = "right-option mb-4",
                style = "border: 1px solid #dc3545; padding: 20px; border-radius: 8px;",
                h5("🗑️ Solicitar Exclusão"),
                p(strong("ATENÇÃO:"), " Esta ação excluirá permanentemente sua conta e todos os dados associados."),
                p("Você perderá acesso à plataforma e não poderá recuperar seus dados posteriormente."),
                checkboxInput(
                  "confirm_deletion",
                  "Confirmo que desejo excluir permanentemente meus dados",
                  value = FALSE
                ),
                actionButton(
                  "request_deletion",
                  "Solicitar Exclusão",
                  class = "btn btn-danger"
                )
              )
            )
          ),
          
          # Data Sharing Tab
          tabPanel(
            "Compartilhamento",
            value = "data_sharing",
            br(),
            
            div(
              class = "sharing-info",
              h4("Como Compartilhamos Seus Dados"),
              
              div(
                class = "alert alert-info",
                h5("🛡️ Compromisso de Privacidade"),
                p("Não vendemos, alugamos ou compartilhamos seus dados pessoais com terceiros para fins comerciais.")
              ),
              
              h5("Compartilhamento Autorizado:"),
              tags$ul(
                tags$li("Provedores de infraestrutura (Railway, Google Cloud) para hospedar a plataforma"),
                tags$li("Provedores de autenticação (Google, Microsoft) apenas para login"),
                tags$li("Autoridades competentes quando exigido por lei")
              ),
              
              h5("Transferências Internacionais:"),
              p("Alguns dados podem ser processados em servidores localizados fora do Brasil, 
                sempre com garantias adequadas de proteção conforme a LGPD."),
              
              h5("Retenção de Dados:"),
              tags$ul(
                tags$li("Dados de conta: até 7 anos após inatividade"),
                tags$li("Logs de acesso: 5 anos para auditoria"),
                tags$li("Dados acadêmicos: conforme regulamentação universitária")
              )
            )
          )
        )
      )
    )
  )
}

#' Process LGPD consent from user
#' @param user_id User identifier
#' @param data_processing_consent Boolean for data processing
#' @param marketing_consent Boolean for marketing communications
process_lgpd_consent <- function(user_id, data_processing_consent, marketing_consent) {
  if (is.null(.db_pool)) {
    return(list(success = FALSE, message = "Sistema indisponível"))
  }
  
  tryCatch({
    # Record consent in database
    dbExecute(.db_pool,
      "UPDATE users 
       SET data_processing_consent = $2, 
           marketing_consent = $3,
           consent_date = CURRENT_TIMESTAMP,
           last_consent_update = CURRENT_TIMESTAMP,
           consent_version = '1.0'
       WHERE id = $1",
      params = list(user_id, data_processing_consent, marketing_consent)
    )
    
    # Log consent action for audit
    log_data_access(
      user_id, NULL, "consent_update", "user_profile", NULL,
      paste("data_processing:", data_processing_consent, "marketing:", marketing_consent)
    )
    
    log_event(paste("LGPD consent processed for user:", user_id))
    
    return(list(
      success = TRUE, 
      message = "Consentimento registrado com sucesso",
      can_access_platform = data_processing_consent
    ))
    
  }, error = function(e) {
    log_event(paste("Consent processing error:", e$message), "ERROR")
    return(list(success = FALSE, message = "Erro ao processar consentimento"))
  })
}

#' Get user access history for LGPD transparency
#' @param user_id User identifier
#' @param start_date Start date for history
#' @param end_date End date for history
#' @return Data frame with access history
get_user_access_history <- function(user_id, start_date = Sys.Date() - 30, end_date = Sys.Date()) {
  if (is.null(.db_pool)) {
    return(data.frame())
  }
  
  tryCatch({
    access_history <- dbGetQuery(.db_pool,
      "SELECT 
         timestamp as 'Data/Hora',
         action_type as 'Ação',
         resource_type as 'Recurso',
         search_criteria as 'Critério de Busca',
         results_count as 'Resultados',
         ip_address as 'IP'
       FROM data_access_log 
       WHERE user_id = $1 
       AND timestamp::date BETWEEN $2 AND $3
       ORDER BY timestamp DESC
       LIMIT 1000",
      params = list(user_id, start_date, end_date)
    )
    
    # Translate action types to Portuguese
    action_translations <- c(
      "view" = "Visualização",
      "search" = "Pesquisa", 
      "export" = "Exportação",
      "download" = "Download",
      "login" = "Login",
      "logout" = "Logout"
    )
    
    if (nrow(access_history) > 0) {
      access_history$Ação <- action_translations[access_history$Ação] %||% access_history$Ação
      access_history$`Data/Hora` <- format(as.POSIXct(access_history$`Data/Hora`), "%d/%m/%Y %H:%M")
    }
    
    return(access_history)
    
  }, error = function(e) {
    log_event(paste("Access history error:", e$message), "ERROR")
    return(data.frame())
  })
}

#' Create data subject request
#' @param user_id User identifier  
#' @param request_type Type of request
#' @param description Request description
#' @return Request ID or NULL on error
create_data_subject_request <- function(user_id, request_type, description = NULL) {
  if (is.null(.db_pool)) {
    return(NULL)
  }
  
  tryCatch({
    request_id <- UUIDgenerate()
    
    dbExecute(.db_pool,
      "INSERT INTO data_subject_requests (
        id, user_id, request_type, request_description, status
      ) VALUES ($1, $2, $3, $4, 'pending')",
      params = list(request_id, user_id, request_type, description)
    )
    
    # Log the request
    log_data_access(user_id, NULL, "data_subject_request", "privacy_rights", NULL, 
                   paste("request_type:", request_type))
    
    # Send notification to administrators
    notify_admin_data_request(request_id, user_id, request_type)
    
    log_event(paste("Data subject request created:", request_id))
    return(request_id)
    
  }, error = function(e) {
    log_event(paste("Data request creation error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Export user data for LGPD portability right
#' @param user_id User identifier
#' @return File path to exported data or NULL on error
export_user_data <- function(user_id) {
  if (is.null(.db_pool)) {
    return(NULL)
  }
  
  tryCatch({
    # Get user data
    user_data <- dbGetQuery(.db_pool,
      "SELECT id, email, full_name, institutional_affiliation, 
              created_at, last_login, consent_version, consent_date
       FROM users WHERE id = $1",
      params = list(user_id)
    )
    
    # Get access history
    access_data <- dbGetQuery(.db_pool,
      "SELECT timestamp, action_type, resource_type, search_criteria, results_count
       FROM data_access_log WHERE user_id = $1 
       ORDER BY timestamp DESC",
      params = list(user_id)
    )
    
    # Get role assignments
    roles_data <- dbGetQuery(.db_pool,
      "SELECT ur.role_name, ur.role_description, ura.assigned_at
       FROM user_role_assignments ura
       JOIN user_roles ur ON ura.role_id = ur.id
       WHERE ura.user_id = $1 AND ura.is_active = true",
      params = list(user_id)
    )
    
    # Combine all data
    export_data <- list(
      user_profile = user_data,
      access_history = access_data,
      roles = roles_data,
      export_info = list(
        generated_at = Sys.time(),
        data_categories = c("identificação", "uso_da_plataforma", "preferências"),
        legal_basis = "direito_de_portabilidade_lgpd"
      )
    )
    
    # Create export file
    export_dir <- "exports"
    if (!dir.exists(export_dir)) {
      dir.create(export_dir, recursive = TRUE)
    }
    
    filename <- paste0("dados_usuario_", gsub("-", "", user_id), "_", 
                      format(Sys.time(), "%Y%m%d_%H%M%S"), ".json")
    filepath <- file.path(export_dir, filename)
    
    # Write JSON file
    write(toJSON(export_data, pretty = TRUE, auto_unbox = TRUE), filepath)
    
    log_event(paste("User data exported:", filepath))
    return(filepath)
    
  }, error = function(e) {
    log_event(paste("Data export error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Notify administrators of data subject request
notify_admin_data_request <- function(request_id, user_id, request_type) {
  # In a production environment, this would send email notifications
  # For now, we'll log the notification
  
  log_event(paste("ADMIN NOTIFICATION: Data subject request", request_id, 
                 "from user", user_id, "type:", request_type), "INFO")
  
  # TODO: Implement email notification to DPO/administrators
  # - Send email to privacy@mackenzie.br
  # - Include request details and due date (15 days per LGPD)
  # - Set up automated reminders
}

#' Check if user needs to update consent (for policy changes)
needs_consent_update <- function(user_session) {
  current_version <- "1.0"
  user_version <- user_session$consent_version %||% "0.0"
  
  return(user_version != current_version)
}

#' LGPD compliance check for data processing
check_lgpd_compliance <- function(user_session, action_type) {
  # Check if user has given required consent
  if (!user_session$data_processing_consent && action_type %in% c("search", "export", "view")) {
    return(list(
      compliant = FALSE,
      message = "Consentimento para processamento de dados é necessário para esta ação.",
      redirect_to_consent = TRUE
    ))
  }
  
  # Check if consent needs update
  if (needs_consent_update(user_session)) {
    return(list(
      compliant = FALSE,
      message = "Política de privacidade foi atualizada. Confirme seu consentimento.",
      redirect_to_consent = TRUE
    ))
  }
  
  return(list(compliant = TRUE))
}

#' Generate LGPD compliance report (for internal use)
generate_compliance_report <- function(start_date = Sys.Date() - 30, end_date = Sys.Date()) {
  if (is.null(.db_pool)) {
    return(NULL)
  }
  
  tryCatch({
    # User consent statistics
    consent_stats <- dbGetQuery(.db_pool,
      "SELECT 
         COUNT(*) as total_users,
         SUM(CASE WHEN data_processing_consent THEN 1 ELSE 0 END) as data_consent_count,
         SUM(CASE WHEN marketing_consent THEN 1 ELSE 0 END) as marketing_consent_count,
         COUNT(*) - SUM(CASE WHEN data_processing_consent THEN 1 ELSE 0 END) as pending_consent
       FROM users WHERE account_status = 'active'"
    )
    
    # Data subject requests
    request_stats <- dbGetQuery(.db_pool,
      "SELECT 
         request_type,
         status,
         COUNT(*) as count,
         AVG(EXTRACT(days FROM (completed_at - created_at))) as avg_resolution_days
       FROM data_subject_requests 
       WHERE created_at::date BETWEEN $1 AND $2
       GROUP BY request_type, status",
      params = list(start_date, end_date)
    )
    
    # Data retention status
    retention_stats <- dbGetQuery(.db_pool,
      "SELECT 
         COUNT(*) as total_records,
         SUM(CASE WHEN data_retention_until < CURRENT_TIMESTAMP THEN 1 ELSE 0 END) as expired_records,
         SUM(CASE WHEN deletion_requested_at IS NOT NULL THEN 1 ELSE 0 END) as deletion_requests
       FROM users"
    )
    
    report <- list(
      generated_at = Sys.time(),
      period = list(start_date = start_date, end_date = end_date),
      consent_compliance = consent_stats,
      data_subject_requests = request_stats,
      data_retention = retention_stats,
      recommendations = generate_compliance_recommendations(consent_stats, request_stats)
    )
    
    return(report)
    
  }, error = function(e) {
    log_event(paste("Compliance report error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Generate compliance recommendations
generate_compliance_recommendations <- function(consent_stats, request_stats) {
  recommendations <- c()
  
  # Check consent rates
  consent_rate <- consent_stats$data_consent_count / consent_stats$total_users
  if (consent_rate < 0.95) {
    recommendations <- c(recommendations, 
      paste("Taxa de consentimento baixa:", round(consent_rate * 100, 1), 
            "%. Revisar processo de consentimento."))
  }
  
  # Check pending requests
  if (nrow(request_stats) > 0) {
    pending_requests <- sum(request_stats$count[request_stats$status == "pending"])
    if (pending_requests > 0) {
      recommendations <- c(recommendations,
        paste("Existem", pending_requests, "solicitações pendentes. Verificar prazos LGPD."))
    }
  }
  
  return(recommendations)
}

log_event("LGPD Compliance Module loaded - Brazilian Data Protection Law")