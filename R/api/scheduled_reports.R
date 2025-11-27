# ==============================================================================
# SCHEDULED REPORTS API ENDPOINTS
# ==============================================================================
# API endpoints for Cloud Scheduler to trigger automated report generation
# and email delivery
#
# Author: Monitor Legislativo Team
# Date: 2025-11-27
# Version: 1.0
# Week 3 - Task 3.3
# ==============================================================================

# Source required utilities
if (file.exists("R/utils/kpi_calculations.R")) source("R/utils/kpi_calculations.R")
if (file.exists("R/utils/pdf_generator.R")) source("R/utils/pdf_generator.R")
if (file.exists("R/utils/html_report_generator.R")) source("R/utils/html_report_generator.R")
if (file.exists("R/utils/cloud_storage.R")) source("R/utils/cloud_storage.R")
if (file.exists("R/utils/email_sender.R")) source("R/utils/email_sender.R")

#' Generate and Send Daily Executive Report
#'
#' API endpoint called by Cloud Scheduler to generate daily executive reports
#' and send them via email
#'
#' @param req Plumber request object
#' @param res Plumber response object
#' @param db_pool Database connection pool
#' @return JSON response with status
#' @export
generate_daily_executive_report <- function(req, res, db_pool) {
  cat("\n📊 === Daily Executive Report Generation Started ===\n")
  cat("   Timestamp:", format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), "\n")

  tryCatch({
    # Parse request body
    body <- req$body
    if (is.null(body)) body <- list()

    recipients <- body$email_recipients %||% c("sofiadonario@hotmail.com")
    include_pdf <- body$include_pdf %||% TRUE
    include_html <- body$include_html %||% FALSE
    send_email_flag <- body$send_email %||% TRUE

    cat("   Recipients:", paste(recipients, collapse = ", "), "\n")
    cat("   Include PDF:", include_pdf, "\n")
    cat("   Send email:", send_email_flag, "\n\n")

    # Fetch data from materialized views
    cat("1️⃣ Fetching KPI data...\n")
    kpis <- get_executive_kpis(db_pool)
    state_summary <- get_state_summary(db_pool, top_n = 10)
    monthly_trends <- get_monthly_trends(db_pool, months = 12)

    if (!is.null(kpis$error)) {
      stop("Failed to fetch KPIs: ", kpis$error)
    }

    # Prepare report data for email template
    today <- Sys.Date()
    yesterday <- today - 1
    period <- format(yesterday, "%d/%m/%Y")

    report_data <- list(
      period = period,
      document_count = format(kpis$total_documents, big.mark = ".", decimal.mark = ","),
      states_count = kpis$states_covered,
      new_documents = format(kpis$docs_last_7_days, big.mark = ".", decimal.mark = ","),
      highlights = paste0(
        "<li>", kpis$docs_last_7_days, " novos documentos nos últimos 7 dias</li>",
        "<li>", kpis$docs_last_30_days, " documentos publicados no último mês</li>",
        "<li>", kpis$states_covered, " estados com legislação monitorada</li>"
      ),
      document_types = "Leis, Decretos, Portarias, Resoluções e outros atos normativos"
    )

    # Generate report file
    report_path <- NULL
    if (include_pdf) {
      cat("2️⃣ Generating PDF report...\n")
      report_path <- generate_executive_pdf(kpis, state_summary, monthly_trends)
      if (is.null(report_path)) {
        stop("PDF generation failed")
      }
      cat("   ✅ PDF created:", basename(report_path), "\n")
    }

    # Upload to Cloud Storage
    cat("3️⃣ Uploading to Cloud Storage...\n")
    upload_result <- upload_report_and_share(report_path, expires_in_hours = 72)
    if (is.null(upload_result)) {
      stop("Upload to Cloud Storage failed")
    }
    report_url <- upload_result$signed_url
    cat("   ✅ Uploaded. Link expires:", format(upload_result$expires_at, "%Y-%m-%d %H:%M"), "\n")

    # Send email
    if (send_email_flag) {
      cat("4️⃣ Sending email...\n")
      for (recipient in recipients) {
        email_result <- send_report_email(
          to = recipient,
          report_data = report_data,
          report_url = report_url,
          attachment_path = NULL  # Link only, no attachment
        )

        if (email_result$status == "success") {
          cat("   ✅ Email sent to:", recipient, "(ID:", email_result$email_id, ")\n")
        } else {
          warning("   ❌ Failed to send email to:", recipient)
        }
      }
    }

    # Clean up local file
    if (!is.null(report_path) && file.exists(report_path)) {
      file.remove(report_path)
    }

    cat("\n✅ === Daily Executive Report Complete ===\n\n")

    # Return success response
    res$status <- 200
    return(list(
      status = "success",
      report_type = "daily_executive",
      recipients = recipients,
      report_url = report_url,
      email_sent = send_email_flag,
      timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z")
    ))

  }, error = function(e) {
    cat("\n❌ === Daily Executive Report Failed ===\n")
    cat("   Error:", e$message, "\n\n")

    res$status <- 500
    return(list(
      status = "error",
      error = e$message,
      timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z")
    ))
  })
}

#' Generate and Send Weekly Summary Report
#'
#' API endpoint for weekly legislative summaries (every Monday)
#'
#' @param req Plumber request object
#' @param res Plumber response object
#' @param db_pool Database connection pool
#' @return JSON response with status
#' @export
generate_weekly_summary_report <- function(req, res, db_pool) {
  cat("\n📊 === Weekly Summary Report Generation Started ===\n")
  cat("   Timestamp:", format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), "\n")

  tryCatch({
    # Parse request body
    body <- req$body
    if (is.null(body)) body <- list()

    recipients <- body$email_recipients %||% c("sofiadonario@hotmail.com")
    include_pdf <- body$include_pdf %||% TRUE
    send_email_flag <- body$send_email %||% TRUE

    # Calculate week period
    today <- Sys.Date()
    week_start <- today - 7
    period <- sprintf("%s a %s",
                     format(week_start, "%d/%m/%Y"),
                     format(today, "%d/%m/%Y"))

    cat("   Period:", period, "\n")
    cat("   Recipients:", paste(recipients, collapse = ", "), "\n\n")

    # Fetch data
    cat("1️⃣ Fetching weekly data...\n")
    kpis <- get_executive_kpis(db_pool)
    state_summary <- get_state_summary(db_pool, top_n = 10)
    monthly_trends <- get_monthly_trends(db_pool, months = 12)

    # Prepare report data
    report_data <- list(
      period = period,
      document_count = format(kpis$total_documents, big.mark = ".", decimal.mark = ","),
      states_count = kpis$states_covered,
      new_documents = format(kpis$docs_last_7_days, big.mark = ".", decimal.mark = ","),
      highlights = paste0(
        "<li><strong>", kpis$docs_last_7_days, " novos documentos</strong> publicados nesta semana</li>",
        "<li>Crescimento de ", round(kpis$growth_rate_7d, 1), "% em relação à semana anterior</li>",
        "<li>Estados mais ativos: ", paste(head(state_summary$state, 3), collapse = ", "), "</li>"
      ),
      document_types = "Leis, Decretos, Portarias, Resoluções e outros atos normativos"
    )

    # Generate PDF
    if (include_pdf) {
      cat("2️⃣ Generating PDF report...\n")
      report_path <- generate_executive_pdf(kpis, state_summary, monthly_trends)
      cat("   ✅ PDF created\n")
    }

    # Upload and send
    cat("3️⃣ Uploading to Cloud Storage...\n")
    upload_result <- upload_report_and_share(report_path, expires_in_hours = 168) # 7 days
    report_url <- upload_result$signed_url

    if (send_email_flag) {
      cat("4️⃣ Sending weekly summary emails...\n")
      for (recipient in recipients) {
        email_result <- send_report_email(
          to = recipient,
          report_data = report_data,
          report_url = report_url
        )
        if (email_result$status == "success") {
          cat("   ✅ Email sent to:", recipient, "\n")
        }
      }
    }

    # Clean up
    if (file.exists(report_path)) file.remove(report_path)

    cat("\n✅ === Weekly Summary Report Complete ===\n\n")

    res$status <- 200
    return(list(
      status = "success",
      report_type = "weekly_summary",
      recipients = recipients,
      report_url = report_url,
      timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z")
    ))

  }, error = function(e) {
    cat("\n❌ === Weekly Summary Report Failed ===\n")
    cat("   Error:", e$message, "\n\n")

    res$status <- 500
    return(list(
      status = "error",
      error = e$message,
      timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z")
    ))
  })
}

#' Manual Report Trigger (for testing)
#'
#' Allows manual triggering of reports for testing purposes
#'
#' @param req Plumber request object
#' @param res Plumber response object
#' @param db_pool Database connection pool
#' @return JSON response with status
#' @export
trigger_manual_report <- function(req, res, db_pool) {
  cat("\n🧪 === Manual Report Trigger ===\n")

  body <- req$body
  report_type <- body$report_type %||% "daily"

  if (report_type == "daily") {
    return(generate_daily_executive_report(req, res, db_pool))
  } else if (report_type == "weekly") {
    return(generate_weekly_summary_report(req, res, db_pool))
  } else {
    res$status <- 400
    return(list(
      status = "error",
      error = "Invalid report_type. Use 'daily' or 'weekly'"
    ))
  }
}

# Null coalescing operator
`%||%` <- function(x, y) {
  if (is.null(x) || length(x) == 0) y else x
}

cat("✅ Scheduled Reports API endpoints loaded\n")
