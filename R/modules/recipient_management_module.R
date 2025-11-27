# ==============================================================================
# RECIPIENT MANAGEMENT MODULE
# ==============================================================================
# Shiny module for managing email recipients for automated reports
#
# Author: Monitor Legislativo Team
# Date: 2025-11-27
# Version: 1.0
# Week 3 - Task 3.4
# ==============================================================================

# Check and load required packages
RECIPIENT_MGMT_DEPENDENCIES <- requireNamespace("shiny", quietly = TRUE) &&
                                requireNamespace("DBI", quietly = TRUE) &&
                                requireNamespace("DT", quietly = TRUE)

if (!RECIPIENT_MGMT_DEPENDENCIES) {
  warning("Recipient management dependencies not available (shiny, DBI, DT)")
}

#' Recipient Management UI
#'
#' @param id Module namespace ID
#' @return Shiny UI elements
#' @export
recipient_management_ui <- function(id) {
  ns <- NS(id)

  tagList(
    # Header
    div(
      style = "margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #28a745;",

      h3(
        HTML("<i class='fa fa-users'></i> Gerenciamento de Destinatários"),
        style = "margin-top: 0; margin-bottom: 10px;"
      ),

      p(
        "Gerencie os destinatários que receberão relatórios executivos automatizados.",
        style = "color: #6c757d; margin-bottom: 0;"
      )
    ),

    # Action buttons
    fluidRow(
      column(12,
        actionButton(
          ns("add_recipient"),
          HTML("<i class='fa fa-plus'></i> Adicionar Destinatário"),
          class = "btn-success",
          style = "margin-bottom: 20px;"
        ),
        actionButton(
          ns("refresh_list"),
          HTML("<i class='fa fa-sync-alt'></i> Atualizar Lista"),
          class = "btn-info",
          style = "margin-bottom: 20px; margin-left: 10px;"
        )
      )
    ),

    # Recipients table
    fluidRow(
      column(12,
        div(
          style = "background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);",
          DTOutput(ns("recipients_table"))
        )
      )
    ),

    # Add/Edit modal
    bslib::modal_dialog(
      id = ns("recipient_modal"),
      title = textOutput(ns("modal_title")),
      size = "l",
      easy_close = TRUE,

      fluidRow(
        column(6,
          textInput(
            ns("modal_email"),
            "Email *",
            placeholder = "usuario@exemplo.com"
          )
        ),
        column(6,
          textInput(
            ns("modal_name"),
            "Nome",
            placeholder = "Nome completo"
          )
        )
      ),

      fluidRow(
        column(6,
          textInput(
            ns("modal_role"),
            "Cargo/Função",
            placeholder = "Ex: Pesquisador, Gestor"
          )
        ),
        column(6,
          textInput(
            ns("modal_organization"),
            "Organização",
            placeholder = "Ex: Universidade, Empresa"
          )
        )
      ),

      h5("Preferências de Relatórios", style = "margin-top: 20px;"),

      fluidRow(
        column(4,
          checkboxInput(ns("modal_daily"), "Relatórios Diários", value = TRUE)
        ),
        column(4,
          checkboxInput(ns("modal_weekly"), "Relatórios Semanais", value = TRUE)
        ),
        column(4,
          checkboxInput(ns("modal_monthly"), "Relatórios Mensais", value = FALSE)
        )
      ),

      fluidRow(
        column(4,
          checkboxInput(ns("modal_urgent"), "Alertas Urgentes", value = TRUE)
        ),
        column(4,
          checkboxInput(ns("modal_pdf"), "Formato PDF", value = TRUE)
        ),
        column(4,
          checkboxInput(ns("modal_html"), "Formato HTML", value = FALSE)
        )
      ),

      textAreaInput(
        ns("modal_notes"),
        "Observações",
        placeholder = "Notas adicionais sobre este destinatário",
        rows = 3
      ),

      footer = tagList(
        actionButton(ns("modal_save"), "Salvar", class = "btn-primary"),
        actionButton(ns("modal_cancel"), "Cancelar", class = "btn-secondary")
      )
    )
  )
}

#' Recipient Management Server
#'
#' @param id Module namespace ID
#' @param db_pool Database connection pool
#' @return Server logic
#' @export
recipient_management_server <- function(id, db_pool) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Reactive values
    recipients_data <- reactiveVal(NULL)
    selected_recipient_id <- reactiveVal(NULL)
    modal_mode <- reactiveVal("add")  # "add" or "edit"

    # Load recipients from database
    load_recipients <- function() {
      tryCatch({
        query <- "
          SELECT
            id,
            email,
            name,
            role,
            organization,
            daily_reports,
            weekly_reports,
            monthly_reports,
            urgent_alerts,
            prefer_pdf,
            prefer_html,
            active,
            verified,
            created_at,
            last_email_sent,
            email_count,
            notes
          FROM report_recipients
          ORDER BY created_at DESC
        "

        data <- dbGetQuery(db_pool, query)
        recipients_data(data)

        showNotification(
          sprintf("✅ %d destinatários carregados", nrow(data)),
          type = "message",
          duration = 3
        )

      }, error = function(e) {
        showNotification(
          paste("❌ Erro ao carregar destinatários:", e$message),
          type = "error",
          duration = 5
        )
      })
    }

    # Load recipients on start
    load_recipients()

    # Refresh button
    observeEvent(input$refresh_list, {
      load_recipients()
    })

    # Recipients table
    output$recipients_table <- renderDT({
      req(recipients_data())

      data <- recipients_data()

      # Format for display
      display_data <- data.frame(
        ID = data$id,
        Email = data$email,
        Nome = data$name,
        Diário = ifelse(data$daily_reports, "✓", ""),
        Semanal = ifelse(data$weekly_reports, "✓", ""),
        Mensal = ifelse(data$monthly_reports, "✓", ""),
        PDF = ifelse(data$prefer_pdf, "✓", ""),
        Ativo = ifelse(data$active, "✅", "❌"),
        Emails = data$email_count,
        Último = format(as.POSIXct(data$last_email_sent), "%d/%m/%Y %H:%M"),
        stringsAsFactors = FALSE
      )

      # Replace NA with "-"
      display_data[is.na(display_data)] <- "-"

      datatable(
        display_data,
        selection = "single",
        options = list(
          pageLength = 10,
          language = list(
            url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json"
          ),
          dom = 'frtip',
          buttons = c('copy', 'csv', 'excel')
        ),
        rownames = FALSE
      )
    })

    # Add recipient button
    observeEvent(input$add_recipient, {
      modal_mode("add")
      selected_recipient_id(NULL)

      # Clear all fields
      updateTextInput(session, "modal_email", value = "")
      updateTextInput(session, "modal_name", value = "")
      updateTextInput(session, "modal_role", value = "")
      updateTextInput(session, "modal_organization", value = "")
      updateCheckboxInput(session, "modal_daily", value = TRUE)
      updateCheckboxInput(session, "modal_weekly", value = TRUE)
      updateCheckboxInput(session, "modal_monthly", value = FALSE)
      updateCheckboxInput(session, "modal_urgent", value = TRUE)
      updateCheckboxInput(session, "modal_pdf", value = TRUE)
      updateCheckboxInput(session, "modal_html", value = FALSE)
      updateTextAreaInput(session, "modal_notes", value = "")

      showModal(modalDialog(
        title = "Adicionar Destinatário",
        recipient_management_ui(id)$children[[4]]$children
      ))
    })

    # Modal title
    output$modal_title <- renderText({
      if (modal_mode() == "add") {
        "Adicionar Novo Destinatário"
      } else {
        "Editar Destinatário"
      }
    })

    # Save recipient
    observeEvent(input$modal_save, {
      # Validate email
      email <- trimws(input$modal_email)
      if (nchar(email) == 0) {
        showNotification("❌ Email é obrigatório", type = "error")
        return()
      }

      if (!grepl("^[^@]+@[^@]+\\.[^@]+$", email)) {
        showNotification("❌ Email inválido", type = "error")
        return()
      }

      tryCatch({
        if (modal_mode() == "add") {
          # Insert new recipient
          query <- "
            INSERT INTO report_recipients (
              email, name, role, organization,
              daily_reports, weekly_reports, monthly_reports, urgent_alerts,
              prefer_pdf, prefer_html, notes, active, verified
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE, FALSE)
          "

          dbExecute(db_pool, query, params = list(
            email,
            input$modal_name,
            input$modal_role,
            input$modal_organization,
            input$modal_daily,
            input$modal_weekly,
            input$modal_monthly,
            input$modal_urgent,
            input$modal_pdf,
            input$modal_html,
            input$modal_notes
          ))

          showNotification("✅ Destinatário adicionado com sucesso!", type = "message")

        } else {
          # Update existing recipient
          query <- "
            UPDATE report_recipients
            SET
              name = $1,
              role = $2,
              organization = $3,
              daily_reports = $4,
              weekly_reports = $5,
              monthly_reports = $6,
              urgent_alerts = $7,
              prefer_pdf = $8,
              prefer_html = $9,
              notes = $10
            WHERE id = $11
          "

          dbExecute(db_pool, query, params = list(
            input$modal_name,
            input$modal_role,
            input$modal_organization,
            input$modal_daily,
            input$modal_weekly,
            input$modal_monthly,
            input$modal_urgent,
            input$modal_pdf,
            input$modal_html,
            input$modal_notes,
            selected_recipient_id()
          ))

          showNotification("✅ Destinatário atualizado com sucesso!", type = "message")
        }

        # Reload data and close modal
        load_recipients()
        removeModal()

      }, error = function(e) {
        showNotification(
          paste("❌ Erro ao salvar:", e$message),
          type = "error",
          duration = 5
        )
      })
    })

    # Cancel button
    observeEvent(input$modal_cancel, {
      removeModal()
    })
  })
}

cat("✅ Recipient Management Module loaded\n")
