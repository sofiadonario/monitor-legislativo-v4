# ============================================================================
# MODULE MANAGER - Monitor Legislativo v4
# Sistema de Gerenciamento de Módulos
# ============================================================================

library(R6)

#' ModuleManager - Sistema de Gerenciamento de Módulos
#' 
#' Gerencia o carregamento, registro e execução de módulos da aplicação
#' com sistema de dependências e fallbacks.
ModuleManager <- R6::R6Class("ModuleManager",
  public = list(
    #' @field modules Lista de módulos registrados
    modules = list(),
    
    #' @field dependencies Mapeamento de dependências entre módulos
    dependencies = list(),
    
    #' @field load_order Ordem de carregamento dos módulos
    load_order = character(0),
    
    #' @field loaded_status Status de carregamento de cada módulo
    loaded_status = list(),
    
    #' @description Inicializa o ModuleManager
    initialize = function() {
      cat("🔧 Inicializando ModuleManager...\n")
      self$setup_core_modules()
    },
    
    #' @description Registra um módulo no sistema
    #' @param name Nome do módulo
    #' @param module Objeto do módulo
    #' @param dependencies Vetor de dependências (opcional)
    #' @param priority Prioridade de carregamento (menor = mais prioritário)
    register_module = function(name, module, dependencies = character(0), priority = 100) {
      if (name %in% names(self$modules)) {
        warning("Módulo '", name, "' já está registrado. Sobrescrevendo...")
      }
      
      self$modules[[name]] <- list(
        module = module,
        dependencies = dependencies,
        priority = priority,
        loaded = FALSE,
        error = NULL
      )
      
      self$dependencies[[name]] <- dependencies
      cat("✅ Módulo '", name, "' registrado com prioridade", priority, "\n")
    },
    
    #' @description Carrega um módulo específico
    #' @param name Nome do módulo
    #' @param force Forçar recarregamento mesmo se já carregado
    load_module = function(name, force = FALSE) {
      if (!name %in% names(self$modules)) {
        stop("Módulo '", name, "' não encontrado")
      }
      
      if (self$modules[[name]]$loaded && !force) {
        cat("ℹ️ Módulo '", name, "' já está carregado\n")
        return(TRUE)
      }
      
      # Verificar dependências
      if (!self$check_dependencies(name)) {
        stop("Dependências não satisfeitas para o módulo '", name, "'")
      }
      
      # Carregar módulo
      tryCatch({
        module_info <- self$modules[[name]]
        
        # Se for um arquivo R, source
        if (is.character(module_info$module)) {
          source(module_info$module)
        }
        # Se for uma função, executar
        else if (is.function(module_info$module)) {
          module_info$module()
        }
        
        self$modules[[name]]$loaded <- TRUE
        self$modules[[name]]$error <- NULL
        self$loaded_status[[name]] <- "success"
        
        cat("✅ Módulo '", name, "' carregado com sucesso\n")
        return(TRUE)
        
      }, error = function(e) {
        self$modules[[name]]$loaded <- FALSE
        self$modules[[name]]$error <- e$message
        self$loaded_status[[name]] <- "error"
        
        cat("❌ Erro ao carregar módulo '", name, "':", e$message, "\n")
        return(FALSE)
      })
    },
    
    #' @description Carrega todos os módulos na ordem correta
    #' @param force Forçar recarregamento de todos os módulos
    load_all_modules = function(force = FALSE) {
      cat("🔄 Carregando todos os módulos...\n")
      
      # Calcular ordem de carregamento baseada em dependências
      self$calculate_load_order()
      
      success_count <- 0
      total_count <- length(self$modules)
      
      for (module_name in self$load_order) {
        if (self$load_module(module_name, force)) {
          success_count <- success_count + 1
        }
      }
      
      cat("📊 Carregamento concluído:", success_count, "/", total_count, "módulos\n")
      return(success_count == total_count)
    },
    
    #' @description Obtém um módulo carregado
    #' @param name Nome do módulo
    get_module = function(name) {
      if (!name %in% names(self$modules)) {
        stop("Módulo '", name, "' não encontrado")
      }
      
      if (!self$modules[[name]]$loaded) {
        warning("Módulo '", name, "' não está carregado")
      }
      
      return(self$modules[[name]]$module)
    },
    
    #' @description Lista status de todos os módulos
    get_status = function() {
      status_df <- data.frame(
        module = names(self$modules),
        loaded = sapply(self$modules, function(x) x$loaded),
        priority = sapply(self$modules, function(x) x$priority),
        dependencies = sapply(self$modules, function(x) paste(x$dependencies, collapse = ", ")),
        error = sapply(self$modules, function(x) if(is.null(x$error)) "" else x$error),
        stringsAsFactors = FALSE
      )
      
      return(status_df)
    },
    
    #' @description Verifica se todas as dependências estão satisfeitas
    #' @param module_name Nome do módulo
    check_dependencies = function(module_name) {
      deps <- self$dependencies[[module_name]]
      if (length(deps) == 0) return(TRUE)
      
      for (dep in deps) {
        if (!dep %in% names(self$modules) || !self$modules[[dep]]$loaded) {
          return(FALSE)
        }
      }
      return(TRUE)
    },
    
    #' @description Calcula ordem de carregamento baseada em dependências
    calculate_load_order = function() {
      # Ordenar por prioridade primeiro
      priority_order <- names(self$modules)[order(sapply(self$modules, function(x) x$priority))]
      
      # Aplicar ordenação topológica para dependências
      self$load_order <- self$topological_sort(priority_order)
    },
    
    #' @description Ordenação topológica para resolver dependências
    #' @param modules Lista de módulos
    topological_sort = function(modules) {
      visited <- setNames(rep(FALSE, length(modules)), modules)
      temp_visited <- setNames(rep(FALSE, length(modules)), modules)
      result <- character(0)
      
      visit <- function(module) {
        if (temp_visited[module]) {
          stop("Dependência circular detectada envolvendo: ", module)
        }
        if (visited[module]) return
        
        temp_visited[module] <<- TRUE
        
        # Visitar dependências primeiro
        deps <- self$dependencies[[module]]
        for (dep in deps) {
          if (dep %in% modules) {
            visit(dep)
          }
        }
        
        temp_visited[module] <<- FALSE
        visited[module] <<- TRUE
        result <<- c(module, result)
      }
      
      for (module in modules) {
        if (!visited[module]) {
          visit(module)
        }
      }
      
      return(result)
    },
    
    #' @description Configura módulos core do sistema
    setup_core_modules = function() {
      # Módulo de dados
      self$register_module(
        "data_loader",
        "modules/data_processing/real_data_loader.R",
        dependencies = character(0),
        priority = 10
      )
      
      # Módulo de integração R-Python
      self$register_module(
        "r_python_bridge",
        "modules/integration/r_python_bridge.R",
        dependencies = character(0),
        priority = 20
      )
      
      # Módulo de processamento em background
      self$register_module(
        "background_processor",
        "modules/background/queue_system.R",
        dependencies = c("r_python_bridge"),
        priority = 30
      )
      
      # Módulos de aplicação (dependem dos anteriores)
      app_modules <- c("analytics", "geographic", "search", "nlp", "citations")
      for (module in app_modules) {
        self$register_module(
          module,
          paste0("modules/application/", module, "/"),
          dependencies = c("data_loader", "r_python_bridge"),
          priority = 50
        )
      }
      
      cat("🔧 Módulos core configurados\n")
    }
  )
)

# Instância global do ModuleManager
module_manager <- ModuleManager$new()

# Funções de conveniência
load_module <- function(name, force = FALSE) {
  module_manager$load_module(name, force)
}

load_all_modules <- function(force = FALSE) {
  module_manager$load_all_modules(force)
}

get_module <- function(name) {
  module_manager$get_module(name)
}

get_module_status <- function() {
  module_manager$get_status()
}

# Exportar para uso global
assign("module_manager", module_manager, envir = .GlobalEnv)
assign("load_module", load_module, envir = .GlobalEnv)
assign("load_all_modules", load_all_modules, envir = .GlobalEnv)
assign("get_module", get_module, envir = .GlobalEnv)
assign("get_module_status", get_module_status, envir = .GlobalEnv)

cat("✅ ModuleManager carregado e disponível globalmente\n")
