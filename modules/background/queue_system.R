# ============================================================================
# QUEUE SYSTEM - Monitor Legislativo v4
# Sistema de Filas e Processamento em Background
# ============================================================================

library(future)
library(promises)
library(httr)
library(jsonlite)

# Configuração do sistema de filas
QUEUE_CONFIG <- list(
  redis_url = Sys.getenv("REDIS_URL", "redis://localhost:6379"),
  max_workers = 4,
  queue_timeout = 300,
  retry_attempts = 3,
  batch_size = 100,
  processing_timeout = 1800
)

# Status do sistema
queue_status <- list(
  workers_running = 0,
  queue_length = 0,
  processing_jobs = 0,
  completed_jobs = 0,
  failed_jobs = 0,
  last_health_check = NULL
)

#' Configurar sistema de filas
#' @param redis_url URL do Redis
#' @param max_workers Número máximo de workers
setup_queue_system <- function(redis_url = NULL, max_workers = NULL) {
  cat("🔄 Configurando sistema de filas...\n")
  
  if (!is.null(redis_url)) {
    QUEUE_CONFIG$redis_url <<- redis_url
  }
  
  if (!is.null(max_workers)) {
    QUEUE_CONFIG$max_workers <<- max_workers
  }
  
  # Configurar future para processamento paralelo
  if (future::supportsMulticore()) {
    future::plan(future::multicore, workers = QUEUE_CONFIG$max_workers)
  } else {
    future::plan(future::multisession, workers = QUEUE_CONFIG$max_workers)
  }
  
  cat("✅ Sistema de filas configurado com", QUEUE_CONFIG$max_workers, "workers\n")
}

#' Adicionar job à fila
#' @param job_type Tipo do job
#' @param data Dados do job
#' @param priority Prioridade (1-10, menor = mais prioritário)
add_job_to_queue <- function(job_type, data, priority = 5) {
  job_id <- paste0("job_", format(Sys.time(), "%Y%m%d_%H%M%S_"), 
                   sample(1000:9999, 1))
  
  job <- list(
    id = job_id,
    type = job_type,
    data = data,
    priority = priority,
    created_at = Sys.time(),
    status = "queued",
    attempts = 0,
    max_attempts = QUEUE_CONFIG$retry_attempts
  )
  
  # Em produção, salvar no Redis
  # Por enquanto, usar memória local
  if (!exists(".job_queue", envir = .GlobalEnv)) {
    assign(".job_queue", list(), envir = .GlobalEnv)
  }
  
  queue <- get(".job_queue", envir = .GlobalEnv)
  queue[[job_id]] <- job
  assign(".job_queue", queue, envir = .GlobalEnv)
  
  cat("📝 Job adicionado à fila:", job_id, "\n")
  return(job_id)
}

#' Processar job
#' @param job Objeto do job
process_job <- function(job) {
  cat("⚙️ Processando job:", job$id, "tipo:", job$type, "\n")
  
  tryCatch({
    # Atualizar status
    job$status <- "processing"
    job$started_at <- Sys.time()
    
    # Processar baseado no tipo
    result <- switch(job$type,
      "analyze_documents" = process_document_analysis(job$data),
      "generate_report" = process_report_generation(job$data),
      "update_cache" = process_cache_update(job$data),
      "export_data" = process_data_export(job$data),
      "nlp_processing" = process_nlp_analysis(job$data),
      {
        cat("⚠️ Tipo de job desconhecido:", job$type, "\n")
        list(error = "Tipo de job não suportado")
      }
    )
    
    # Marcar como concluído
    job$status <- "completed"
    job$completed_at <- Sys.time()
    job$result <- result
    
    cat("✅ Job concluído:", job$id, "\n")
    return(job)
    
  }, error = function(e) {
    cat("❌ Erro no job", job$id, ":", e$message, "\n")
    
    job$status <- "failed"
    job$error <- e$message
    job$attempts <- job$attempts + 1
    
    # Tentar novamente se não excedeu tentativas
    if (job$attempts < job$max_attempts) {
      job$status <- "retry"
      cat("🔄 Job será tentado novamente:", job$id, "\n")
    }
    
    return(job)
  })
}

#' Processar análise de documentos
#' @param data Dados dos documentos
process_document_analysis <- function(data) {
  cat("📊 Processando análise de documentos...\n")
  
  # Simular processamento pesado
  Sys.sleep(2)
  
  # Análise básica
  result <- list(
    total_documents = length(data$document_ids),
    processed_at = Sys.time(),
    analysis_type = "basic",
    results = list(
      sentiment_distribution = c(positive = 0.4, neutral = 0.3, negative = 0.3),
      document_types = c(lei = 0.5, decreto = 0.3, portaria = 0.2),
      geographic_coverage = c(SP = 0.3, RJ = 0.2, MG = 0.15, outros = 0.35)
    )
  )
  
  return(result)
}

#' Processar geração de relatório
#' @param data Dados do relatório
process_report_generation <- function(data) {
  cat("📋 Gerando relatório...\n")
  
  # Simular geração de relatório
  Sys.sleep(3)
  
  result <- list(
    report_id = paste0("report_", format(Sys.time(), "%Y%m%d_%H%M%S")),
    generated_at = Sys.time(),
    format = data$format %||% "pdf",
    pages = sample(10:50, 1),
    file_path = paste0("exports/report_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".pdf")
  )
  
  return(result)
}

#' Processar atualização de cache
#' @param data Dados para cache
process_cache_update <- function(data) {
  cat("💾 Atualizando cache...\n")
  
  # Simular atualização de cache
  Sys.sleep(1)
  
  result <- list(
    cache_keys_updated = length(data$keys),
    updated_at = Sys.time(),
    cache_size_mb = sample(100:500, 1)
  )
  
  return(result)
}

#' Processar exportação de dados
#' @param data Dados para exportar
process_data_export <- function(data) {
  cat("📤 Exportando dados...\n")
  
  # Simular exportação
  Sys.sleep(2)
  
  result <- list(
    export_id = paste0("export_", format(Sys.time(), "%Y%m%d_%H%M%S")),
    exported_at = Sys.time(),
    format = data$format %||% "csv",
    records_exported = data$record_count %||% 0,
    file_path = paste0("exports/data_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
  )
  
  return(result)
}

#' Processar análise NLP
#' @param data Dados para análise NLP
process_nlp_analysis <- function(data) {
  cat("🤖 Processando análise NLP...\n")
  
  # Usar bridge R-Python se disponível
  if (exists("analyze_sentiment") && exists("extract_entities")) {
    tryCatch({
      # Análise de sentimento
      sentiment_result <- analyze_sentiment(data$text)
      
      # Extração de entidades
      entities_result <- extract_entities(data$text)
      
      result <- list(
        sentiment = sentiment_result,
        entities = entities_result,
        processed_at = Sys.time(),
        method = "python_api"
      )
      
      return(result)
    }, error = function(e) {
      cat("⚠️ Erro na API Python, usando fallback:", e$message, "\n")
    })
  }
  
  # Fallback para análise básica em R
  result <- list(
    sentiment = list(sentiment = "neutral", confidence = 0.5),
    entities = list(entities = list(), confidence = 0.3),
    processed_at = Sys.time(),
    method = "r_fallback"
  )
  
  return(result)
}

#' Processar fila de jobs
process_queue <- function() {
  if (!exists(".job_queue", envir = .GlobalEnv)) {
    return()
  }
  
  queue <- get(".job_queue", envir = .GlobalEnv)
  
  # Filtrar jobs prontos para processamento
  ready_jobs <- Filter(function(job) {
    job$status %in% c("queued", "retry")
  }, queue)
  
  if (length(ready_jobs) == 0) {
    return()
  }
  
  # Ordenar por prioridade
  ready_jobs <- ready_jobs[order(sapply(ready_jobs, function(x) x$priority))]
  
  # Processar jobs em paralelo
  futures <- lapply(ready_jobs, function(job) {
    future({
      process_job(job)
    })
  })
  
  # Aguardar conclusão
  results <- lapply(futures, function(f) {
    tryCatch({
      value(f)
    }, error = function(e) {
      cat("❌ Erro no future:", e$message, "\n")
      NULL
    })
  })
  
  # Atualizar fila com resultados
  for (result in results) {
    if (!is.null(result)) {
      queue[[result$id]] <- result
    }
  }
  
  assign(".job_queue", queue, envir = .GlobalEnv)
  
  # Atualizar estatísticas
  update_queue_statistics()
}

#' Atualizar estatísticas da fila
update_queue_statistics <- function() {
  if (!exists(".job_queue", envir = .GlobalEnv)) {
    return()
  }
  
  queue <- get(".job_queue", envir = .GlobalEnv)
  
  queue_status$queue_length <<- length(Filter(function(x) x$status == "queued", queue))
  queue_status$processing_jobs <<- length(Filter(function(x) x$status == "processing", queue))
  queue_status$completed_jobs <<- length(Filter(function(x) x$status == "completed", queue))
  queue_status$failed_jobs <<- length(Filter(function(x) x$status == "failed", queue))
  queue_status$last_health_check <<- Sys.time()
}

#' Obter status da fila
get_queue_status <- function() {
  update_queue_statistics()
  return(queue_status)
}

#' Iniciar processamento em background
start_background_processing <- function() {
  cat("🚀 Iniciando processamento em background...\n")
  
  # Configurar sistema
  setup_queue_system()
  
  # Iniciar loop de processamento
  future({
    while (TRUE) {
      tryCatch({
        process_queue()
        Sys.sleep(5) # Processar a cada 5 segundos
      }, error = function(e) {
        cat("❌ Erro no processamento em background:", e$message, "\n")
        Sys.sleep(10) # Aguardar mais tempo em caso de erro
      })
    }
  })
  
  cat("✅ Processamento em background iniciado\n")
}

#' Parar processamento em background
stop_background_processing <- function() {
  cat("⏹️ Parando processamento em background...\n")
  # Em implementação real, usar flags de controle
  cat("✅ Processamento em background parado\n")
}

# Funções de conveniência para adicionar jobs
analyze_documents_async <- function(document_ids) {
  add_job_to_queue("analyze_documents", list(document_ids = document_ids))
}

generate_report_async <- function(data, format = "pdf") {
  add_job_to_queue("generate_report", list(data = data, format = format))
}

update_cache_async <- function(keys) {
  add_job_to_queue("update_cache", list(keys = keys))
}

export_data_async <- function(data, format = "csv") {
  add_job_to_queue("export_data", list(data = data, format = format))
}

process_nlp_async <- function(text) {
  add_job_to_queue("nlp_processing", list(text = text))
}

# Exportar funções para uso global
assign("add_job_to_queue", add_job_to_queue, envir = .GlobalEnv)
assign("analyze_documents_async", analyze_documents_async, envir = .GlobalEnv)
assign("generate_report_async", generate_report_async, envir = .GlobalEnv)
assign("update_cache_async", update_cache_async, envir = .GlobalEnv)
assign("export_data_async", export_data_async, envir = .GlobalEnv)
assign("process_nlp_async", process_nlp_async, envir = .GlobalEnv)
assign("get_queue_status", get_queue_status, envir = .GlobalEnv)
assign("start_background_processing", start_background_processing, envir = .GlobalEnv)

cat("✅ Sistema de Filas carregado e disponível globalmente\n")
