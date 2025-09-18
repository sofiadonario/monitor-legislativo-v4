# ============================================================================
# R-PYTHON BRIDGE - Monitor Legislativo v4
# Sistema de Integração Robusta com Fallback
# ============================================================================

library(httr)
library(jsonlite)
library(reticulate)

# Configuração do Bridge
BRIDGE_CONFIG <- list(
  python_api_url = "http://localhost:8080",
  timeout_seconds = 30,
  retry_attempts = 3,
  retry_delay = 2,
  fallback_enabled = TRUE,
  health_check_interval = 60
)

# Status do bridge
bridge_status <- list(
  python_available = FALSE,
  api_available = FALSE,
  last_health_check = NULL,
  fallback_mode = FALSE
)

#' Configurar integração Python
#' @param python_path Caminho para o Python (opcional)
#' @param api_url URL da API Python (opcional)
configure_python_integration <- function(python_path = NULL, api_url = NULL) {
  cat("🔧 Configurando integração R-Python...\n")
  
  # Configurar reticulate
  if (!is.null(python_path)) {
    tryCatch({
      reticulate::use_python(python_path, required = FALSE)
      bridge_status$python_available <<- TRUE
      cat("✅ Python configurado:", python_path, "\n")
    }, error = function(e) {
      cat("⚠️ Erro ao configurar Python:", e$message, "\n")
      bridge_status$python_available <<- FALSE
    })
  } else {
    # Tentar detectar Python automaticamente
    python_paths <- c(
      "/usr/bin/python3",
      "/usr/local/bin/python3",
      "python3",
      "python"
    )
    
    for (path in python_paths) {
      if (system(paste("which", path), ignore.stdout = TRUE) == 0) {
        tryCatch({
          reticulate::use_python(path, required = FALSE)
          bridge_status$python_available <<- TRUE
          cat("✅ Python detectado automaticamente:", path, "\n")
          break
        }, error = function(e) {
          cat("⚠️ Erro com Python em", path, ":", e$message, "\n")
        })
      }
    }
  }
  
  # Configurar URL da API
  if (!is.null(api_url)) {
    BRIDGE_CONFIG$python_api_url <<- api_url
  }
  
  # Verificar saúde da API
  check_python_api_health()
  
  # Configurar fallback se necessário
  if (!bridge_status$api_available && BRIDGE_CONFIG$fallback_enabled) {
    setup_fallback_mode()
  }
}

#' Verificar saúde da API Python
check_python_api_health <- function() {
  tryCatch({
    response <- httr::GET(
      paste0(BRIDGE_CONFIG$python_api_url, "/health"),
      timeout(BRIDGE_CONFIG$timeout_seconds)
    )
    
    if (httr::status_code(response) == 200) {
      bridge_status$api_available <<- TRUE
      bridge_status$last_health_check <<- Sys.time()
      cat("✅ API Python disponível\n")
      return(TRUE)
    } else {
      bridge_status$api_available <<- FALSE
      cat("⚠️ API Python retornou status:", httr::status_code(response), "\n")
      return(FALSE)
    }
  }, error = function(e) {
    bridge_status$api_available <<- FALSE
    cat("❌ Erro ao verificar API Python:", e$message, "\n")
    return(FALSE)
  })
}

#' Configurar modo de fallback
setup_fallback_mode <- function() {
  cat("🔄 Configurando modo de fallback (processamento R puro)...\n")
  bridge_status$fallback_mode <<- TRUE
  
  # Carregar funções de fallback
  if (file.exists("modules/integration/r_fallback_processing.R")) {
    source("modules/integration/r_fallback_processing.R")
    cat("✅ Funções de fallback carregadas\n")
  } else {
    cat("⚠️ Arquivo de fallback não encontrado, criando funções básicas...\n")
    create_basic_fallback_functions()
  }
}

#' Criar funções básicas de fallback
create_basic_fallback_functions <- function() {
  # Função de fallback para análise de sentimento
  sentiment_analysis_fallback <<- function(text) {
    # Análise básica de sentimento em R
    positive_words <- c("bom", "ótimo", "excelente", "positivo", "benefício")
    negative_words <- c("ruim", "péssimo", "negativo", "problema", "dificuldade")
    
    text_lower <- tolower(text)
    positive_count <- sum(sapply(positive_words, function(w) length(grep(w, text_lower))))
    negative_count <- sum(sapply(negative_words, function(w) length(grep(w, text_lower))))
    
    if (positive_count > negative_count) {
      return(list(sentiment = "positive", confidence = 0.6))
    } else if (negative_count > positive_count) {
      return(list(sentiment = "negative", confidence = 0.6))
    } else {
      return(list(sentiment = "neutral", confidence = 0.5))
    }
  }
  
  # Função de fallback para classificação de documentos
  document_classification_fallback <<- function(title, content) {
    # Classificação básica baseada em palavras-chave
    if (grepl("lei|decreto|portaria", tolower(title))) {
      return(list(type = "legislacao", confidence = 0.7))
    } else if (grepl("acórdão|decisão|sentença", tolower(title))) {
      return(list(type = "jurisprudencia", confidence = 0.7))
    } else {
      return(list(type = "outros", confidence = 0.5))
    }
  }
  
  cat("✅ Funções básicas de fallback criadas\n")
}

#' Chamar serviço Python com retry e fallback
#' @param endpoint Endpoint da API
#' @param data Dados para enviar
#' @param method Método HTTP (GET, POST, etc.)
call_python_service <- function(endpoint, data = NULL, method = "POST") {
  # Verificar se API está disponível
  if (!bridge_status$api_available) {
    if (bridge_status$fallback_mode) {
      cat("🔄 Usando modo de fallback para:", endpoint, "\n")
      return(process_with_fallback(endpoint, data))
    } else {
      stop("API Python não disponível e fallback não configurado")
    }
  }
  
  # Tentar chamada com retry
  for (attempt in 1:BRIDGE_CONFIG$retry_attempts) {
    tryCatch({
      url <- paste0(BRIDGE_CONFIG$python_api_url, "/", endpoint)
      
      if (method == "GET") {
        response <- httr::GET(url, timeout(BRIDGE_CONFIG$timeout_seconds))
      } else {
        response <- httr::POST(
          url,
          body = data,
          encode = "json",
          timeout(BRIDGE_CONFIG$timeout_seconds)
        )
      }
      
      if (httr::status_code(response) == 200) {
        result <- httr::content(response, as = "parsed")
        return(result)
      } else {
        cat("⚠️ Tentativa", attempt, "falhou com status:", httr::status_code(response), "\n")
      }
      
    }, error = function(e) {
      cat("⚠️ Tentativa", attempt, "falhou com erro:", e$message, "\n")
    })
    
    if (attempt < BRIDGE_CONFIG$retry_attempts) {
      Sys.sleep(BRIDGE_CONFIG$retry_delay)
    }
  }
  
  # Se todas as tentativas falharam, usar fallback
  if (BRIDGE_CONFIG$fallback_enabled) {
    cat("🔄 Todas as tentativas falharam, usando fallback para:", endpoint, "\n")
    return(process_with_fallback(endpoint, data))
  } else {
    stop("Falha ao chamar serviço Python após", BRIDGE_CONFIG$retry_attempts, "tentativas")
  }
}

#' Processar com funções de fallback
#' @param endpoint Endpoint solicitado
#' @param data Dados para processar
process_with_fallback <- function(endpoint, data) {
  switch(endpoint,
    "analyze_sentiment" = {
      if (!is.null(data$text)) {
        sentiment_analysis_fallback(data$text)
      } else {
        list(sentiment = "neutral", confidence = 0.5)
      }
    },
    "classify_document" = {
      if (!is.null(data$title) && !is.null(data$content)) {
        document_classification_fallback(data$title, data$content)
      } else {
        list(type = "outros", confidence = 0.5)
      }
    },
    "extract_entities" = {
      # Fallback básico para extração de entidades
      list(entities = list(), confidence = 0.3)
    },
    {
      # Fallback genérico
      list(
        processed = TRUE,
        method = "r_fallback",
        confidence = 0.3,
        message = "Processado com fallback R"
      )
    }
  )
}

#' Análise de sentimento com fallback
#' @param text Texto para analisar
analyze_sentiment <- function(text) {
  call_python_service("analyze_sentiment", list(text = text))
}

#' Classificação de documento com fallback
#' @param title Título do documento
#' @param content Conteúdo do documento
classify_document <- function(title, content) {
  call_python_service("classify_document", list(title = title, content = content))
}

#' Extração de entidades com fallback
#' @param text Texto para extrair entidades
extract_entities <- function(text) {
  call_python_service("extract_entities", list(text = text))
}

#' Obter status do bridge
get_bridge_status <- function() {
  return(list(
    python_available = bridge_status$python_available,
    api_available = bridge_status$api_available,
    fallback_mode = bridge_status$fallback_mode,
    last_health_check = bridge_status$last_health_check,
    config = BRIDGE_CONFIG
  ))
}

#' Inicializar bridge
initialize_bridge <- function() {
  cat("🌉 Inicializando R-Python Bridge...\n")
  
  # Configurar integração
  configure_python_integration()
  
  # Verificar status
  status <- get_bridge_status()
  cat("📊 Status do Bridge:\n")
  cat("   Python disponível:", status$python_available, "\n")
  cat("   API disponível:", status$api_available, "\n")
  cat("   Modo fallback:", status$fallback_mode, "\n")
  
  return(status)
}

# Inicializar automaticamente
bridge_status <- initialize_bridge()

# Exportar funções para uso global
assign("analyze_sentiment", analyze_sentiment, envir = .GlobalEnv)
assign("classify_document", classify_document, envir = .GlobalEnv)
assign("extract_entities", extract_entities, envir = .GlobalEnv)
assign("get_bridge_status", get_bridge_status, envir = .GlobalEnv)

cat("✅ R-Python Bridge carregado e disponível globalmente\n")
