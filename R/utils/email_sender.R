# ==============================================================================
# EMAIL SENDER UTILITY - RESEND INTEGRATION
# ==============================================================================
# Professional email delivery for Monitor Legislativo reports
# Integrates with Resend API and GCP Secret Manager
#
# Author: Monitor Legislativo Team
# Date: 2025-11-27
# Version: 1.0
# Week 3 - Task 3.2
# ==============================================================================

library(httr)
library(jsonlite)

# Resend API configuration
RESEND_API_URL <- "https://api.resend.com/emails"
RESEND_API_KEY_SECRET <- "resend-api-key"

#' Get Resend API Key from Secret Manager
#'
#' Retrieves the API key securely from GCP Secret Manager
#'
#' @return Character string with API key, or NULL if failed
#' @export
get_resend_api_key <- function() {
  tryCatch({
    # Try to get from Secret Manager
    cmd <- sprintf(
      "gcloud secrets versions access latest --secret=%s --project=mackmonitor",
      RESEND_API_KEY_SECRET
    )

    api_key <- system(cmd, intern = TRUE, ignore.stderr = TRUE)

    if (length(api_key) == 0 || nchar(api_key) == 0) {
      warning("Failed to retrieve Resend API key from Secret Manager")
      return(NULL)
    }

    return(trimws(api_key))

  }, error = function(e) {
    warning("Error retrieving Resend API key: ", e$message)
    return(NULL)
  })
}

#' Send Email via Resend API
#'
#' Sends an email using the Resend service with support for HTML content
#' and attachments (PDF/HTML reports).
#'
#' @param to Character vector. Recipient email address(es)
#' @param subject Character. Email subject line
#' @param html_content Character. HTML email body
#' @param from Character. Sender email (default: Monitor Legislativo)
#' @param attachments List. Optional attachments (see details)
#' @param reply_to Character. Optional reply-to address
#' @return List with send status and email ID, or NULL if failed
#'
#' @details
#' Attachments should be a list with the following structure:
#' list(
#'   list(
#'     filename = "report.pdf",
#'     content = base64_encoded_content,
#'     content_type = "application/pdf"
#'   )
#' )
#'
#' @examples
#' \dontrun{
#' send_email(
#'   to = "user@example.com",
#'   subject = "Weekly Report",
#'   html_content = "<h1>Report</h1><p>Content here</p>"
#' )
#' }
#' @export
send_email <- function(to,
                      subject,
                      html_content,
                      from = "Monitor Legislativo <noreply@resend.dev>",
                      attachments = NULL,
                      reply_to = NULL) {

  cat("📧 Sending email via Resend...\n")
  cat("   To:", paste(to, collapse = ", "), "\n")
  cat("   Subject:", subject, "\n")

  tryCatch({
    # Get API key
    api_key <- get_resend_api_key()
    if (is.null(api_key)) {
      stop("Resend API key not available")
    }

    # Build request body
    body <- list(
      from = from,
      to = to,
      subject = subject,
      html = html_content
    )

    # Add optional fields
    if (!is.null(reply_to)) {
      body$reply_to <- reply_to
    }

    if (!is.null(attachments) && length(attachments) > 0) {
      body$attachments <- attachments
      cat("   Attachments:", length(attachments), "file(s)\n")
    }

    # Send request to Resend API
    response <- POST(
      url = RESEND_API_URL,
      add_headers(
        Authorization = paste("Bearer", api_key),
        "Content-Type" = "application/json"
      ),
      body = toJSON(body, auto_unbox = TRUE),
      encode = "json"
    )

    # Parse response
    response_content <- content(response, as = "parsed")

    # Check for errors
    if (status_code(response) != 200) {
      error_msg <- if (!is.null(response_content$message)) {
        response_content$message
      } else {
        paste("HTTP", status_code(response))
      }
      stop("Resend API error: ", error_msg)
    }

    # Success
    email_id <- response_content$id
    cat("✅ Email sent successfully! ID:", email_id, "\n")

    return(list(
      status = "success",
      email_id = email_id,
      timestamp = Sys.time()
    ))

  }, error = function(e) {
    cat("❌ Email sending failed:", e$message, "\n")
    return(list(
      status = "error",
      error = e$message,
      timestamp = Sys.time()
    ))
  })
}

#' Send Report Email with Template
#'
#' Sends a legislative report email using the pre-built HTML template
#' with variable substitution and optional PDF/HTML attachments.
#'
#' @param to Character vector. Recipient email address(es)
#' @param report_data List. Data to populate template (period, document_count, etc.)
#' @param report_url Character. Cloud Storage signed URL for report download
#' @param attachment_path Character. Optional local path to PDF/HTML file to attach
#' @return List with send status
#' @export
send_report_email <- function(to,
                              report_data,
                              report_url,
                              attachment_path = NULL) {

  cat("📊 Sending report email...\n")

  tryCatch({
    # Read email template
    template_path <- "R/templates/email_report_template.html"
    if (!file.exists(template_path)) {
      warning("Email template not found, using simple HTML")
      html_content <- generate_simple_report_html(report_data, report_url)
    } else {
      template <- readLines(template_path, warn = FALSE)
      html_content <- paste(template, collapse = "\n")

      # Substitute variables
      html_content <- gsub("\\{\\{period\\}\\}", report_data$period %||% "N/A", html_content)
      html_content <- gsub("\\{\\{document_count\\}\\}", report_data$document_count %||% "0", html_content)
      html_content <- gsub("\\{\\{states_count\\}\\}", report_data$states_count %||% "0", html_content)
      html_content <- gsub("\\{\\{new_documents\\}\\}", report_data$new_documents %||% "0", html_content)
      html_content <- gsub("\\{\\{download_url\\}\\}", report_url, html_content)
      html_content <- gsub("\\{\\{highlights\\}\\}", report_data$highlights %||% "<li>Nenhum destaque disponível</li>", html_content)
      html_content <- gsub("\\{\\{document_types\\}\\}", report_data$document_types %||% "Diversos tipos", html_content)
      html_content <- gsub("\\{\\{unsubscribe_url\\}\\}", "#", html_content)
    }

    # Prepare attachments if provided
    attachments <- NULL
    if (!is.null(attachment_path) && file.exists(attachment_path)) {
      cat("   Preparing attachment:", basename(attachment_path), "\n")

      # Read file and encode to base64
      file_content <- readBin(attachment_path, "raw", file.info(attachment_path)$size)
      encoded_content <- base64enc::base64encode(file_content)

      # Determine content type
      ext <- tools::file_ext(attachment_path)
      content_type <- switch(ext,
        pdf = "application/pdf",
        html = "text/html",
        "application/octet-stream"
      )

      attachments <- list(
        list(
          filename = basename(attachment_path),
          content = encoded_content,
          content_type = content_type
        )
      )
    }

    # Generate subject
    subject <- sprintf(
      "Monitor Legislativo - Relatório Executivo (%s)",
      report_data$period %||% format(Sys.Date(), "%Y-%m-%d")
    )

    # Send email
    result <- send_email(
      to = to,
      subject = subject,
      html_content = html_content,
      attachments = attachments
    )

    return(result)

  }, error = function(e) {
    cat("❌ Report email failed:", e$message, "\n")
    return(list(
      status = "error",
      error = e$message,
      timestamp = Sys.time()
    ))
  })
}

#' Generate Simple Report HTML (Fallback)
#'
#' Creates a basic HTML email when template is not available
#'
#' @param report_data List. Report data
#' @param report_url Character. Download URL
#' @return Character. HTML content
#' @keywords internal
generate_simple_report_html <- function(report_data, report_url) {
  html <- sprintf('
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; border-radius: 8px; text-align: center; }
    .content { background: white; padding: 30px; margin-top: 20px; }
    .button { display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
  </style>
</head>
<body>
  <div class="header">
    <h1>📊 Monitor Legislativo</h1>
    <p>Relatório Executivo</p>
  </div>
  <div class="content">
    <h2>Olá!</h2>
    <p>Seu relatório executivo está disponível para download.</p>
    <p><strong>Período:</strong> %s</p>
    <p><strong>Documentos analisados:</strong> %s</p>
    <p><strong>Estados cobertos:</strong> %s</p>
    <a href="%s" class="button">📥 Baixar Relatório</a>
    <p><small>O link expira em 72 horas.</small></p>
  </div>
</body>
</html>
  ',
  report_data$period %||% "N/A",
  report_data$document_count %||% "0",
  report_data$states_count %||% "0",
  report_url
  )

  return(html)
}

#' Test Email Functionality
#'
#' Sends a test email to verify Resend integration is working
#'
#' @param to Character. Test recipient email address
#' @return List with test results
#' @export
test_email_sending <- function(to = "sofiadonario@hotmail.com") {
  cat("🧪 Testing email functionality...\n")

  html_content <- '
<div style="font-family: Arial, sans-serif; padding: 20px;">
  <h1 style="color: #667eea;">✅ Email Test Successful!</h1>
  <p>This is a test email from Monitor Legislativo v4.</p>
  <p>If you received this message, the Resend integration is working correctly.</p>
  <hr>
  <p><small>Monitor Legislativo - Universidade Presbiteriana Mackenzie</small></p>
</div>
  '

  result <- send_email(
    to = to,
    subject = "Test: Monitor Legislativo Email Integration",
    html_content = html_content
  )

  return(result)
}

# Null coalescing operator helper
`%||%` <- function(x, y) {
  if (is.null(x) || length(x) == 0 || (is.character(x) && nchar(x) == 0)) y else x
}

cat("✅ Email Sender module loaded\n")
