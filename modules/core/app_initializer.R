# ============================================================================
# APP INITIALIZER - Monitor Legislativo v4
# Sistema de Inicialização com Módulos
# ============================================================================

#' Inicializar aplicação com sistema de módulos
initialize_app_with_modules <- function() {
  cat("🚀 Inicializando Monitor Legislativo v4 com sistema de módulos...\n")
  
  # 1. Carregar sistema de gerenciamento de módulos
  tryCatch({
    source("modules/core/module_manager.R")
    cat("✅ ModuleManager carregado\n")
  }, error = function(e) {
    cat("❌ Erro ao carregar ModuleManager:", e$message, "\n")
    return(FALSE)
  })
  
  # 2. Carregar sistema de integração R-Python
  tryCatch({
    source("modules/integration/r_python_bridge.R")
    cat("✅ R-Python Bridge carregado\n")
  }, error = function(e) {
    cat("❌ Erro ao carregar R-Python Bridge:", e$message, "\n")
  })
  
  # 3. Carregar sistema de processamento em background
  tryCatch({
    source("modules/background/queue_system.R")
    cat("✅ Sistema de Filas carregado\n")
  }, error = function(e) {
    cat("❌ Erro ao carregar Sistema de Filas:", e$message, "\n")
  })
  
  # 4. Carregar sistema de fallback
  tryCatch({
    source("modules/integration/r_fallback_processing.R")
    cat("✅ Sistema de Fallback carregado\n")
  }, error = function(e) {
    cat("❌ Erro ao carregar Sistema de Fallback:", e$message, "\n")
  })
  
  # 5. Carregar todos os módulos registrados
  tryCatch({
    success <- load_all_modules()
    if (success) {
      cat("✅ Todos os módulos carregados com sucesso\n")
    } else {
      cat("⚠️ Alguns módulos falharam ao carregar\n")
    }
  }, error = function(e) {
    cat("❌ Erro ao carregar módulos:", e$message, "\n")
  })
  
  # 6. Iniciar processamento em background
  tryCatch({
    start_background_processing()
    cat("✅ Processamento em background iniciado\n")
  }, error = function(e) {
    cat("⚠️ Erro ao iniciar processamento em background:", e$message, "\n")
  })
  
  # 7. Exibir status final
  cat("\n📊 STATUS DA INICIALIZAÇÃO:\n")
  cat("============================\n")
  
  # Status do ModuleManager
  if (exists("get_module_status")) {
    module_status <- get_module_status()
    cat("Módulos carregados:", sum(module_status$loaded), "/", nrow(module_status), "\n")
  }
  
  # Status do Bridge
  if (exists("get_bridge_status")) {
    bridge_status <- get_bridge_status()
    cat("Python disponível:", bridge_status$python_available, "\n")
    cat("API disponível:", bridge_status$api_available, "\n")
    cat("Modo fallback:", bridge_status$fallback_mode, "\n")
  }
  
  # Status da Fila
  if (exists("get_queue_status")) {
    queue_status <- get_queue_status()
    cat("Jobs na fila:", queue_status$queue_length, "\n")
    cat("Jobs processando:", queue_status$processing_jobs, "\n")
    cat("Jobs concluídos:", queue_status$completed_jobs, "\n")
  }
  
  cat("============================\n")
  cat("✅ Inicialização concluída!\n\n")
  
  return(TRUE)
}

#' Carregar módulos de aplicação existentes
load_existing_app_modules <- function() {
  cat("🔄 Carregando módulos de aplicação existentes...\n")
  
  # Módulos de analytics
  analytics_files <- list.files("modules/analytics", pattern = "\\.R$", full.names = TRUE)
  for (file in analytics_files) {
    tryCatch({
      source(file)
      cat("✅ Carregado:", basename(file), "\n")
    }, error = function(e) {
      cat("⚠️ Erro ao carregar", basename(file), ":", e$message, "\n")
    })
  }
  
  # Módulos geográficos
  geographic_files <- list.files("modules/geographic", pattern = "\\.R$", full.names = TRUE)
  for (file in geographic_files) {
    tryCatch({
      source(file)
      cat("✅ Carregado:", basename(file), "\n")
    }, error = function(e) {
      cat("⚠️ Erro ao carregar", basename(file), ":", e$message, "\n")
    })
  }
  
  # Módulos de busca
  search_files <- list.files("modules/search", pattern = "\\.R$", full.names = TRUE)
  for (file in search_files) {
    tryCatch({
      source(file)
      cat("✅ Carregado:", basename(file), "\n")
    }, error = function(e) {
      cat("⚠️ Erro ao carregar", basename(file), ":", e$message, "\n")
    })
  }
  
  # Módulos de citações
  citation_files <- list.files("modules/citations", pattern = "\\.R$", full.names = TRUE)
  for (file in citation_files) {
    tryCatch({
      source(file)
      cat("✅ Carregado:", basename(file), "\n")
    }, error = function(e) {
      cat("⚠️ Erro ao carregar", basename(file), ":", e$message, "\n")
    })
  }
  
  cat("✅ Módulos de aplicação carregados\n")
}

#' Verificar saúde do sistema
check_system_health <- function() {
  cat("🏥 Verificando saúde do sistema...\n")
  
  health_status <- list(
    modules = "unknown",
    bridge = "unknown",
    queue = "unknown",
    fallback = "unknown"
  )
  
  # Verificar módulos
  if (exists("get_module_status")) {
    module_status <- get_module_status()
    loaded_count <- sum(module_status$loaded)
    total_count <- nrow(module_status)
    
    if (loaded_count == total_count) {
      health_status$modules <- "healthy"
    } else if (loaded_count > total_count * 0.8) {
      health_status$modules <- "warning"
    } else {
      health_status$modules <- "unhealthy"
    }
  }
  
  # Verificar bridge
  if (exists("get_bridge_status")) {
    bridge_status <- get_bridge_status()
    if (bridge_status$api_available || bridge_status$fallback_mode) {
      health_status$bridge <- "healthy"
    } else {
      health_status$bridge <- "unhealthy"
    }
  }
  
  # Verificar fila
  if (exists("get_queue_status")) {
    queue_status <- get_queue_status()
    if (queue_status$queue_length < 100) {
      health_status$queue <- "healthy"
    } else if (queue_status$queue_length < 500) {
      health_status$queue <- "warning"
    } else {
      health_status$queue <- "unhealthy"
    }
  }
  
  # Verificar fallback
  if (exists("analyze_sentiment_fallback")) {
    health_status$fallback <- "healthy"
  } else {
    health_status$fallback <- "unhealthy"
  }
  
  # Exibir status
  cat("📊 Status de Saúde:\n")
  for (component in names(health_status)) {
    status_icon <- switch(health_status[[component]],
      "healthy" = "✅",
      "warning" = "⚠️",
      "unhealthy" = "❌",
      "unknown" = "❓"
    )
    cat("  ", component, ":", status_icon, health_status[[component]], "\n")
  }
  
  return(health_status)
}

# Exportar funções para uso global
assign("initialize_app_with_modules", initialize_app_with_modules, envir = .GlobalEnv)
assign("load_existing_app_modules", load_existing_app_modules, envir = .GlobalEnv)
assign("check_system_health", check_system_health, envir = .GlobalEnv)

cat("✅ App Initializer carregado e disponível globalmente\n")
