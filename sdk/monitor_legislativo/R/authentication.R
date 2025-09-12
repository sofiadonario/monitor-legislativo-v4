#' @title Autenticação e Configuração da API
#' @description Funções para autenticação e configuração do Monitor Legislativo API
#' @author Monitor Legislativo Research Team
#' @importFrom httr2 request req_headers req_perform req_error
#' @importFrom jsonlite fromJSON toJSON
#' @importFrom keyring key_set key_get key_delete key_list
#' @importFrom cli cli_alert_success cli_alert_error cli_alert_info
#' @importFrom glue glue

# Global package environment for storing configuration
.ml_env <- new.env(parent = emptyenv())

# Default API configuration
.ml_env$base_url <- "https://monitor-legislativo-unified-production.up.railway.app/api/v4"
.ml_env$api_key <- NULL
.ml_env$timeout <- 30
.ml_env$user_agent <- "monitor.legislativo R SDK v1.0.0"
.ml_env$cache_enabled <- TRUE
.ml_env$verbose <- FALSE

#' Configurar chave de API do Monitor Legislativo
#'
#' @description
#' Configura a chave de API necessária para acessar o Monitor Legislativo API.
#' A chave pode ser fornecida diretamente ou armazenada de forma segura usando keyring.
#'
#' @param api_key String. Chave de API fornecida pela equipe do Monitor Legislativo.
#' @param store_securely Logical. Se TRUE, armazena a chave de forma segura usando keyring.
#' @param service_name String. Nome do serviço para armazenamento no keyring.
#' 
#' @return Invisível. Configura a chave de API para uso nas demais funções.
#' 
#' @examples
#' \dontrun{
#' # Configurar chave de API diretamente
#' ml_set_api_key("sua_chave_de_api_aqui")
#' 
#' # Configurar e armazenar de forma segura
#' ml_set_api_key("sua_chave_de_api_aqui", store_securely = TRUE)
#' 
#' # Carregar chave armazenada
#' ml_set_api_key(store_securely = TRUE)
#' }
#' 
#' @export
ml_set_api_key <- function(api_key = NULL, 
                           store_securely = FALSE, 
                           service_name = "monitor_legislativo_api") {
  
  if (store_securely && is.null(api_key)) {
    # Tentar carregar chave do keyring
    tryCatch({
      api_key <- key_get(service_name, username = Sys.info()["user"])
      cli_alert_success("Chave de API carregada do armazenamento seguro")
    }, error = function(e) {
      cli_alert_error("Nenhuma chave de API encontrada no armazenamento seguro")
      cli_alert_info("Use ml_set_api_key('sua_chave') para configurar")
      return(invisible(FALSE))
    })
  }
  
  if (is.null(api_key) || nchar(trimws(api_key)) == 0) {
    cli_alert_error("Chave de API não pode estar vazia")
    return(invisible(FALSE))
  }
  
  # Validar formato da chave de API
  if (!grepl("^[A-Za-z0-9_-]{20,}$", api_key)) {
    cli_alert_error("Formato de chave de API inválido")
    return(invisible(FALSE))
  }
  
  # Armazenar chave de forma segura se solicitado
  if (store_securely && !is.null(api_key)) {
    tryCatch({
      key_set(service_name, username = Sys.info()["user"], password = api_key)
      cli_alert_success("Chave de API armazenada de forma segura")
    }, error = function(e) {
      cli_alert_error(glue("Erro ao armazenar chave: {e$message}"))
    })
  }
  
  # Configurar chave no ambiente do pacote
  .ml_env$api_key <- api_key
  
  # Validar chave com a API
  if (ml_validate_api_key()) {
    cli_alert_success("Chave de API configurada e validada com sucesso")
    return(invisible(TRUE))
  } else {
    cli_alert_error("Chave de API inválida ou servidor indisponível")
    return(invisible(FALSE))
  }
}

#' Autenticar com o Monitor Legislativo API
#'
#' @description
#' Autentica o usuário com o Monitor Legislativo API e recupera informações
#' sobre limites de uso e permissões.
#'
#' @param api_key String. Chave de API (opcional se já configurada).
#' @param check_usage Logical. Se TRUE, também recupera estatísticas de uso.
#' 
#' @return List com informações de autenticação e limites de uso.
#' 
#' @examples
#' \dontrun{
#' # Autenticar e verificar limites
#' auth_info <- ml_authenticate()
#' print(auth_info)
#' 
#' # Autenticar com chave específica
#' auth_info <- ml_authenticate("sua_chave_de_api")
#' }
#' 
#' @export
ml_authenticate <- function(api_key = NULL, check_usage = TRUE) {
  
  # Usar chave fornecida ou chave configurada
  if (!is.null(api_key)) {
    .ml_env$api_key <- api_key
  }
  
  if (is.null(.ml_env$api_key)) {
    cli_alert_error("Chave de API não configurada. Use ml_set_api_key() primeiro.")
    return(NULL)
  }
  
  tryCatch({
    # Validar chave de API
    auth_result <- .ml_api_call("GET", "/auth/validate")
    
    if (is.null(auth_result) || !auth_result$success) {
      cli_alert_error("Falha na autenticação")
      return(NULL)
    }
    
    auth_info <- list(
      authenticated = TRUE,
      user_type = auth_result$data$user_type %||% "academic",
      rate_limits = auth_result$data$rate_limits %||% list(),
      permissions = auth_result$data$permissions %||% list(),
      validated_at = Sys.time()
    )
    
    # Recuperar estatísticas de uso se solicitado
    if (check_usage) {
      usage_result <- .ml_api_call("GET", "/auth/usage")
      if (!is.null(usage_result) && usage_result$success) {
        auth_info$usage_stats <- usage_result$data
      }
    }
    
    cli_alert_success(glue("Autenticado como: {auth_info$user_type}"))
    
    return(auth_info)
    
  }, error = function(e) {
    cli_alert_error(glue("Erro na autenticação: {e$message}"))
    return(NULL)
  })
}

#' Validar chave de API
#'
#' @description
#' Valida se a chave de API configurada é válida e o servidor está acessível.
#'
#' @return Logical. TRUE se a chave é válida, FALSE caso contrário.
#' 
#' @examples
#' \dontrun{
#' # Verificar se a chave atual é válida
#' if (ml_validate_api_key()) {
#'   print("Chave válida")
#' } else {
#'   print("Chave inválida")
#' }
#' }
#' 
#' @export
ml_validate_api_key <- function() {
  
  if (is.null(.ml_env$api_key)) {
    return(FALSE)
  }
  
  tryCatch({
    result <- .ml_api_call("GET", "/auth/validate", timeout = 10)
    return(!is.null(result) && result$success)
  }, error = function(e) {
    return(FALSE)
  })
}

#' Configurar URL base da API
#'
#' @description
#' Configura a URL base da API do Monitor Legislativo. Útil para desenvolvimento
#' ou uso de instâncias alternativas.
#'
#' @param base_url String. URL base da API (sem /api/v4).
#' 
#' @return Invisible TRUE se configuração bem-sucedida.
#' 
#' @examples
#' \dontrun{
#' # Configurar para servidor de desenvolvimento
#' ml_set_base_url("http://localhost:3838")
#' 
#' # Configurar para produção (padrão)
#' ml_set_base_url("https://monitor-legislativo-unified-production.up.railway.app")
#' }
#' 
#' @export
ml_set_base_url <- function(base_url) {
  
  # Validar URL
  if (!grepl("^https?://", base_url)) {
    cli_alert_error("URL deve começar com http:// ou https://")
    return(invisible(FALSE))
  }
  
  # Remover trailing slash e /api/v4 se presente
  base_url <- gsub("/$", "", base_url)
  base_url <- gsub("/api/v4$", "", base_url)
  
  # Configurar URL completa
  .ml_env$base_url <- paste0(base_url, "/api/v4")
  
  cli_alert_success(glue("URL base configurada: {.ml_env$base_url}"))
  return(invisible(TRUE))
}

#' Obter configuração atual
#'
#' @description
#' Retorna a configuração atual do SDK, incluindo URL base, status da chave
#' de API e outras configurações.
#'
#' @return List com configurações atuais.
#' 
#' @examples
#' \dontrun{
#' # Ver configuração atual
#' config <- ml_get_config()
#' print(config)
#' }
#' 
#' @export
ml_get_config <- function() {
  
  config <- list(
    base_url = .ml_env$base_url,
    api_key_configured = !is.null(.ml_env$api_key),
    api_key_length = if (!is.null(.ml_env$api_key)) nchar(.ml_env$api_key) else 0,
    timeout = .ml_env$timeout,
    user_agent = .ml_env$user_agent,
    cache_enabled = .ml_env$cache_enabled,
    verbose = .ml_env$verbose,
    package_version = "1.0.0"
  )
  
  return(config)
}

#' Configurar opções avançadas
#'
#' @description
#' Configura opções avançadas do SDK como timeout, cache e verbosidade.
#'
#' @param timeout Numeric. Timeout em segundos para requisições HTTP.
#' @param cache_enabled Logical. Habilitar cache local de respostas.
#' @param verbose Logical. Habilitar mensagens verbosas.
#' @param user_agent String. User agent personalizado.
#' 
#' @return Invisible TRUE.
#' 
#' @examples
#' \dontrun{
#' # Configurar timeout maior e habilitar verbose
#' ml_set_options(timeout = 60, verbose = TRUE)
#' 
#' # Desabilitar cache
#' ml_set_options(cache_enabled = FALSE)
#' }
#' 
#' @export
ml_set_options <- function(timeout = NULL, 
                          cache_enabled = NULL, 
                          verbose = NULL, 
                          user_agent = NULL) {
  
  if (!is.null(timeout)) {
    if (!is.numeric(timeout) || timeout <= 0) {
      cli_alert_error("Timeout deve ser um número positivo")
      return(invisible(FALSE))
    }
    .ml_env$timeout <- timeout
    cli_alert_info(glue("Timeout configurado para {timeout} segundos"))
  }
  
  if (!is.null(cache_enabled)) {
    .ml_env$cache_enabled <- as.logical(cache_enabled)
    cli_alert_info(glue("Cache {ifelse(.ml_env$cache_enabled, 'habilitado', 'desabilitado')}"))
  }
  
  if (!is.null(verbose)) {
    .ml_env$verbose <- as.logical(verbose)
    cli_alert_info(glue("Modo verbose {ifelse(.ml_env$verbose, 'habilitado', 'desabilitado')}"))
  }
  
  if (!is.null(user_agent)) {
    .ml_env$user_agent <- as.character(user_agent)
    cli_alert_info(glue("User agent configurado: {user_agent}"))
  }
  
  return(invisible(TRUE))
}

#' Limpar configuração
#'
#' @description
#' Remove todas as configurações, incluindo chave de API da memória.
#' Não remove chaves armazenadas no keyring.
#'
#' @param remove_stored_key Logical. Se TRUE, remove também a chave armazenada no keyring.
#' 
#' @return Invisible TRUE.
#' 
#' @examples
#' \dontrun{
#' # Limpar configuração da sessão
#' ml_clear_config()
#' 
#' # Limpar tudo, incluindo chave armazenada
#' ml_clear_config(remove_stored_key = TRUE)
#' }
#' 
#' @export
ml_clear_config <- function(remove_stored_key = FALSE) {
  
  # Remover chave da memória
  .ml_env$api_key <- NULL
  
  # Remover chave armazenada se solicitado
  if (remove_stored_key) {
    tryCatch({
      key_delete("monitor_legislativo_api", username = Sys.info()["user"])
      cli_alert_success("Chave removida do armazenamento seguro")
    }, error = function(e) {
      cli_alert_info("Nenhuma chave encontrada no armazenamento seguro")
    })
  }
  
  cli_alert_success("Configuração limpa")
  return(invisible(TRUE))
}

# Função interna para chamadas à API
.ml_api_call <- function(method, endpoint, body = NULL, timeout = NULL) {
  
  if (is.null(.ml_env$api_key)) {
    stop("Chave de API não configurada. Use ml_set_api_key() primeiro.")
  }
  
  # Construir URL completa
  url <- paste0(.ml_env$base_url, endpoint)
  
  # Configurar timeout
  if (is.null(timeout)) {
    timeout <- .ml_env$timeout
  }
  
  # Criar requisição
  req <- request(url) %>%
    req_headers(
      "X-API-Key" = .ml_env$api_key,
      "User-Agent" = .ml_env$user_agent,
      "Accept" = "application/json",
      "Content-Type" = "application/json"
    )
  
  # Adicionar body se fornecido
  if (!is.null(body)) {
    req <- req %>% req_body_json(body)
  }
  
  # Log se verbose habilitado
  if (.ml_env$verbose) {
    cli_alert_info(glue("API Call: {method} {endpoint}"))
  }
  
  # Executar requisição
  tryCatch({
    resp <- req %>% req_perform()
    result <- resp %>% resp_body_json()
    
    if (.ml_env$verbose) {
      cli_alert_success(glue("API Response: {resp$status_code}"))
    }
    
    return(result)
    
  }, error = function(e) {
    if (.ml_env$verbose) {
      cli_alert_error(glue("API Error: {e$message}"))
    }
    
    # Tentar extrair erro da resposta
    if (inherits(e, "httr2_http_error")) {
      error_body <- tryCatch({
        e$response %>% resp_body_json()
      }, error = function(e2) NULL)
      
      if (!is.null(error_body) && !is.null(error_body$message)) {
        stop(glue("API Error: {error_body$message}"))
      }
    }
    
    stop(glue("Erro na requisição: {e$message}"))
  })
}