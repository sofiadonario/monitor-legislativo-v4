# =============================================================================
# Standardized Error Handling System
# =============================================================================
# Monitor Legislativo v4 - Phase 4: Optimization & Polish
#
# Provides consistent error codes, messages, and user-friendly responses
# Ensures predictable error handling across the application
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

# =============================================================================
# ERROR CODE DEFINITIONS
# =============================================================================

ERROR_CODES <- list(
  # Database Errors (1xxx)
  DB_CONNECTION_FAILED = list(
    code = "DB001",
    message = "Falha na conexão com o banco de dados",
    user_message = "Não foi possível conectar ao banco de dados. Tente novamente em alguns instantes.",
    severity = "CRITICAL"
  ),
  DB_QUERY_FAILED = list(
    code = "DB002",
    message = "Falha na execução da consulta",
    user_message = "Erro ao processar sua solicitação. Por favor, tente novamente.",
    severity = "ERROR"
  ),
  DB_TRANSACTION_FAILED = list(
    code = "DB003",
    message = "Falha na transação do banco de dados",
    user_message = "A operação foi cancelada devido a um erro. Nenhuma alteração foi salva.",
    severity = "ERROR"
  ),
  DB_POOL_EXHAUSTED = list(
    code = "DB004",
    message = "Pool de conexões esgotado",
    user_message = "Sistema temporariamente sobrecarregado. Tente novamente em alguns segundos.",
    severity = "WARNING"
  ),

  # Data Validation Errors (2xxx)
  VALIDATION_FAILED = list(
    code = "VAL001",
    message = "Validação de dados falhou",
    user_message = "Os dados fornecidos são inválidos. Verifique e tente novamente.",
    severity = "WARNING"
  ),
  INVALID_INPUT = list(
    code = "VAL002",
    message = "Entrada inválida detectada",
    user_message = "Entrada inválida. Por favor, verifique os dados inseridos.",
    severity = "WARNING"
  ),
  SQL_INJECTION_ATTEMPT = list(
    code = "SEC001",
    message = "Tentativa de SQL injection detectada",
    user_message = "Entrada bloqueada por motivos de segurança.",
    severity = "CRITICAL"
  ),
  XSS_ATTEMPT = list(
    code = "SEC002",
    message = "Tentativa de XSS detectada",
    user_message = "Entrada bloqueada por motivos de segurança.",
    severity = "CRITICAL"
  ),

  # Resource Errors (3xxx)
  RESOURCE_NOT_FOUND = list(
    code = "RES001",
    message = "Recurso não encontrado",
    user_message = "O item solicitado não foi encontrado.",
    severity = "WARNING"
  ),
  NO_DATA_AVAILABLE = list(
    code = "RES002",
    message = "Nenhum dado disponível",
    user_message = "Nenhum resultado encontrado para os filtros selecionados.",
    severity = "INFO"
  ),
  FILE_NOT_FOUND = list(
    code = "RES003",
    message = "Arquivo não encontrado",
    user_message = "O arquivo solicitado não existe.",
    severity = "WARNING"
  ),

  # Session Errors (4xxx)
  SESSION_EXPIRED = list(
    code = "SESS001",
    message = "Sessão expirada",
    user_message = "Sua sessão expirou. Por favor, recarregue a página.",
    severity = "WARNING"
  ),
  SESSION_INVALID = list(
    code = "SESS002",
    message = "Sessão inválida",
    user_message = "Sessão inválida. Por favor, recarregue a página.",
    severity = "WARNING"
  ),

  # Permission Errors (5xxx)
  PERMISSION_DENIED = list(
    code = "PERM001",
    message = "Permissão negada",
    user_message = "Você não tem permissão para realizar esta ação.",
    severity = "WARNING"
  ),
  UNAUTHORIZED_ACCESS = list(
    code = "PERM002",
    message = "Acesso não autorizado",
    user_message = "Acesso negado.",
    severity = "WARNING"
  ),

  # System Errors (9xxx)
  INTERNAL_ERROR = list(
    code = "SYS001",
    message = "Erro interno do sistema",
    user_message = "Ocorreu um erro inesperado. Nossa equipe foi notificada.",
    severity = "ERROR"
  ),
  FEATURE_NOT_AVAILABLE = list(
    code = "SYS002",
    message = "Funcionalidade não disponível",
    user_message = "Esta funcionalidade está temporariamente indisponível.",
    severity = "INFO"
  ),
  TIMEOUT = list(
    code = "SYS003",
    message = "Tempo limite excedido",
    user_message = "A operação demorou muito tempo. Por favor, tente novamente.",
    severity = "WARNING"
  )
)

# =============================================================================
# ERROR HANDLING FUNCTIONS
# =============================================================================

#' Create Standardized Error Response
#'
#' Creates a consistent error response with code, message, and metadata
#'
#' @param error_type Error type from ERROR_CODES list
#' @param details Additional error details (optional)
#' @param technical_info Technical information for logging (optional)
#'
#' @return List with error information
#' @export
create_error_response <- function(error_type, details = NULL, technical_info = NULL) {

  if (!error_type %in% names(ERROR_CODES)) {
    error_type <- "INTERNAL_ERROR"
  }

  error_def <- ERROR_CODES[[error_type]]

  error_response <- list(
    success = FALSE,
    error = list(
      code = error_def$code,
      message = error_def$message,
      user_message = error_def$user_message,
      severity = error_def$severity,
      timestamp = Sys.time(),
      details = details
    )
  )

  # Log error for monitoring
  log_error_response(error_response, technical_info)

  return(error_response)
}

#' Handle Database Error
#'
#' Standardized handler for database errors
#'
#' @param error Original error object
#' @param context Context where error occurred (optional)
#'
#' @return Standardized error response
#' @export
handle_database_error <- function(error, context = NULL) {

  # Determine specific error type
  error_message <- tolower(error$message)

  if (grepl("connection|connect", error_message)) {
    error_type <- "DB_CONNECTION_FAILED"
  } else if (grepl("transaction|commit|rollback", error_message)) {
    error_type <- "DB_TRANSACTION_FAILED"
  } else if (grepl("pool|timeout", error_message)) {
    error_type <- "DB_POOL_EXHAUSTED"
  } else {
    error_type <- "DB_QUERY_FAILED"
  }

  create_error_response(
    error_type = error_type,
    details = context,
    technical_info = error$message
  )
}

#' Handle Validation Error
#'
#' Standardized handler for data validation errors
#'
#' @param validation_result Validation result object
#' @param field_name Name of the field that failed validation (optional)
#'
#' @return Standardized error response
#' @export
handle_validation_error <- function(validation_result, field_name = NULL) {

  # Check if it's a security issue
  if (!is.null(validation_result$error)) {
    if (grepl("SQL|DROP|DELETE|INSERT", validation_result$error, ignore.case = TRUE)) {
      error_type <- "SQL_INJECTION_ATTEMPT"
    } else if (grepl("script|javascript|XSS", validation_result$error, ignore.case = TRUE)) {
      error_type <- "XSS_ATTEMPT"
    } else {
      error_type <- "INVALID_INPUT"
    }
  } else {
    error_type <- "VALIDATION_FAILED"
  }

  create_error_response(
    error_type = error_type,
    details = list(
      field = field_name,
      validation_error = validation_result$error
    )
  )
}

#' Safe Execute with Error Handling
#'
#' Executes a function with standardized error handling
#'
#' @param expr Expression to execute
#' @param error_handler Function to handle errors (default: create_error_response)
#' @param fallback_value Value to return on error (default: NULL)
#'
#' @return Result of expression or error response
#' @export
safe_execute <- function(expr,
                        error_handler = function(e) create_error_response("INTERNAL_ERROR",
                                                                          technical_info = e$message),
                        fallback_value = NULL) {
  tryCatch(
    expr,
    error = function(e) {
      error_response <- error_handler(e)

      # Log error
      cat(sprintf("\n❌ ERROR [%s]: %s\n",
                 error_response$error$code,
                 error_response$error$message),
          file = stderr())

      if (!is.null(fallback_value)) {
        return(fallback_value)
      }

      return(error_response)
    },
    warning = function(w) {
      cat(sprintf("\n⚠️ WARNING: %s\n", w$message), file = stderr())
      suppressWarnings(expr)
    }
  )
}

# =============================================================================
# ERROR LOGGING
# =============================================================================

#' Log Error Response
#'
#' Logs error for monitoring and debugging
#'
#' @param error_response Error response object
#' @param technical_info Additional technical information
#'
#' @return NULL (logs to console/file)
#' @keywords internal
log_error_response <- function(error_response, technical_info = NULL) {

  # Format log entry
  log_entry <- sprintf(
    "[%s] ERROR %s (%s): %s",
    format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
    error_response$error$code,
    error_response$error$severity,
    error_response$error$message
  )

  if (!is.null(technical_info)) {
    log_entry <- paste0(log_entry, sprintf("\n  Technical: %s", technical_info))
  }

  # Log to stderr (visible in application logs)
  cat(log_entry, "\n", file = stderr())

  # TODO: Integrate with audit logging system if available
  if (exists("log_user_action")) {
    tryCatch({
      log_user_action(
        action = "error_occurred",
        details = error_response$error
      )
    }, error = function(e) {
      # Silently fail if logging not available
    })
  }

  invisible(NULL)
}

# =============================================================================
# SHINY-SPECIFIC ERROR HANDLERS
# =============================================================================

#' Show Error Notification in Shiny
#'
#' Displays user-friendly error notification
#'
#' @param error_response Error response object
#' @param session Shiny session object
#' @param duration Notification duration in seconds (default: 5)
#'
#' @return NULL (shows notification)
#' @export
show_error_notification <- function(error_response, session = NULL, duration = 5) {

  if (!is.null(session) && inherits(session, "ShinySession")) {
    # Use Shiny notification
    showNotification(
      ui = tags$div(
        tags$strong(sprintf("[%s]", error_response$error$code)),
        br(),
        error_response$error$user_message
      ),
      type = if (error_response$error$severity == "CRITICAL") "error"
             else if (error_response$error$severity == "WARNING") "warning"
             else "message",
      duration = duration,
      session = session
    )
  } else {
    # Fallback to console
    cat(sprintf("\n%s: %s\n",
               error_response$error$code,
               error_response$error$user_message))
  }

  invisible(NULL)
}

#' Safe Reactive with Error Handling
#'
#' Wraps a reactive expression with error handling
#'
#' @param expr Reactive expression
#' @param session Shiny session (optional)
#' @param fallback Default value on error
#'
#' @return Reactive value or fallback
#' @export
safe_reactive <- function(expr, session = NULL, fallback = NULL) {
  reactive({
    result <- safe_execute(
      expr,
      fallback_value = fallback
    )

    # Show notification if error occurred
    if (is.list(result) && !is.null(result$error)) {
      show_error_notification(result, session)
      return(fallback)
    }

    return(result)
  })
}

# =============================================================================
# ERROR STATISTICS
# =============================================================================

# Initialize error counter
if (!exists(".error_counter", envir = .GlobalEnv)) {
  assign(".error_counter", new.env(parent = emptyenv()), envir = .GlobalEnv)
}

#' Get Error Statistics
#'
#' Returns statistics about errors that occurred
#'
#' @return Data frame with error statistics
#' @export
get_error_statistics <- function() {
  counter <- get(".error_counter", envir = .GlobalEnv)

  if (length(ls(counter)) == 0) {
    return(data.frame(
      error_code = character(),
      count = integer(),
      last_occurrence = character(),
      stringsAsFactors = FALSE
    ))
  }

  stats <- lapply(ls(counter), function(code) {
    info <- get(code, envir = counter)
    data.frame(
      error_code = code,
      count = info$count,
      last_occurrence = format(info$last_time, "%Y-%m-%d %H:%M:%S"),
      stringsAsFactors = FALSE
    )
  })

  do.call(rbind, stats)
}

#' Reset Error Statistics
#'
#' Clears error counter
#'
#' @export
reset_error_statistics <- function() {
  counter <- get(".error_counter", envir = .GlobalEnv)
  rm(list = ls(counter), envir = counter)
  message("Error statistics reset")
  invisible(NULL)
}

# =============================================================================
# EXAMPLE USAGE
# =============================================================================

# Example 1: Handle database error
# result <- tryCatch({
#   dbGetQuery(pool, "SELECT * FROM table")
# }, error = function(e) {
#   handle_database_error(e, context = "Fetching data from table")
# })

# Example 2: Handle validation error
# validation <- validate_search_term(input$search)
# if (!validation$valid) {
#   error <- handle_validation_error(validation, field_name = "search")
#   show_error_notification(error, session)
#   return()
# }

# Example 3: Safe reactive execution
# data <- safe_reactive({
#   dbGetQuery(db_pool, "SELECT * FROM documents LIMIT 100")
# }, session = session, fallback = data.frame())
