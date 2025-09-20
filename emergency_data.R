# EMERGENCY DATASET GENERATOR FOR RAILWAY DEPLOYMENT
# ===================================================
# This file generates a hard-coded dataset when CSV files are missing
# Contains realistic Brazilian legislative documents with transport-related content

cat("🚨 EMERGENCY DATASET GENERATOR ACTIVATED\n")
cat("========================================\n")

# Load required libraries
suppressWarnings({
  library(dplyr, quietly = TRUE)
  library(stringr, quietly = TRUE)
})

#' Generate Emergency Dataset
#' Creates a realistic dataset of Brazilian legislative documents
#' @param size Number of documents to generate (default: 500)
#' @return data.frame with same structure as CSV files
generate_emergency_dataset <- function(size = 500) {

  cat("Generating emergency dataset with", size, "documents...\n")

  # Set seed for reproducibility
  set.seed(42)

  # Brazilian states and their codes
  estados <- c(
    "SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "ES", "PE",
    "CE", "PA", "MT", "MS", "PB", "RN", "AL", "SE", "PI", "MA",
    "TO", "DF", "RO", "AC", "AM", "RR", "AP", "Federal"
  )

  estado_nomes <- c(
    "São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul",
    "Paraná", "Santa Catarina", "Bahia", "Goiás", "Espírito Santo",
    "Pernambuco", "Ceará", "Pará", "Mato Grosso", "Mato Grosso do Sul",
    "Paraíba", "Rio Grande do Norte", "Alagoas", "Sergipe", "Piauí",
    "Maranhão", "Tocantins", "Distrito Federal", "Rondônia", "Acre",
    "Amazonas", "Roraima", "Amapá", "Federal"
  )

  # Document categories
  categorias <- c("Legislação", "Jurisprudência", "Doutrina")

  # Transport modes
  modais <- c("rodoviário", "ferroviário", "aquaviário", "aeroviário", "dutoviário", "geral")

  # Document types
  tipos <- c(
    "Lei", "Decreto", "Portaria", "Resolução", "Instrução Normativa",
    "Acórdão", "Decisão", "Sentença", "Medida Provisória", "Lei Complementar"
  )

  # Transport-related keywords
  transport_keywords <- c(
    "transporte", "trânsito", "rodovia", "ferrovia", "porto", "aeroporto",
    "estrada", "veículo", "ônibus", "caminhão", "trem", "navio", "avião",
    "combustível", "pedágio", "sinalização", "segurança viária", "licenciamento",
    "ANTT", "ANTAQ", "ANAC", "DENATRAN", "DER", "DNIT", "CNT", "CONAMA",
    "infraestrutura", "mobilidade", "logística", "carga", "passageiro",
    "multimodal", "intermodal", "terminal", "pátio", "via", "acesso"
  )

  # Jurisdiction types
  jurisdicoes <- c("Federal", "Estadual", "Municipal")

  # Authorities
  autoridades <- c(
    "Congresso Nacional", "Assembleia Legislativa", "Câmara Municipal",
    "Presidente da República", "Governador", "Prefeito", "Ministério",
    "Secretaria", "ANTT", "ANTAQ", "ANAC", "DENATRAN", "Tribunal"
  )

  # Generate realistic titles
  generate_title <- function(tipo, keyword, ano, numero = NULL) {
    if (is.null(numero)) numero <- sample(1:9999, 1)

    templates <- c(
      paste0(tipo, " nº ", numero, ", de ", sample(1:28, 1), " de ",
             sample(c("janeiro", "fevereiro", "março", "abril", "maio", "junho",
                     "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"), 1),
             " de ", ano),
      paste0(tipo, " ", numero, "/", ano, " - ", str_to_title(keyword)),
      paste0(tipo, " ", numero, " de ", ano, " sobre ", keyword)
    )

    sample(templates, 1)
  }

  # Generate realistic ementas (summaries)
  generate_ementa <- function(keyword, modal, categoria) {
    base_templates <- c(
      paste0("Dispõe sobre regulamentação de ", keyword, " no modal ", modal, " e dá outras providências."),
      paste0("Estabelece normas para ", keyword, " em ", modal, " considerando aspectos de segurança e eficiência."),
      paste0("Regulamenta atividades de ", keyword, " no setor de ", modal, " conforme legislação vigente."),
      paste0("Define diretrizes para ", keyword, " aplicáveis ao modal ", modal, " no território nacional."),
      paste0("Institui medidas de controle e fiscalização de ", keyword, " em ", modal, "."),
      paste0("Estabelece procedimentos para licenciamento de ", keyword, " no modal ", modal, "."),
      paste0("Dispõe sobre infrações e penalidades relacionadas a ", keyword, " em ", modal, "."),
      paste0("Regulamenta concessão e permissão de serviços de ", keyword, " no modal ", modal, "."),
      paste0("Define critérios técnicos para ", keyword, " aplicáveis ao setor de ", modal, "."),
      paste0("Estabelece política nacional de ", keyword, " para o modal ", modal, ".")
    )

    if (categoria == "Jurisprudência") {
      base_templates <- c(
        paste0("Recurso em processo sobre ", keyword, " no modal ", modal, ". Decisão favorável."),
        paste0("Ação judicial sobre regulamentação de ", keyword, " em ", modal, ". Precedente estabelecido."),
        paste0("Apelação sobre licenciamento de ", keyword, " no setor ", modal, ". Recurso provido."),
        paste0("Mandado de segurança sobre ", keyword, " em ", modal, ". Segurança concedida."),
        paste0("Ação civil pública sobre ", keyword, " no modal ", modal, ". Procedência parcial.")
      )
    }

    sample(base_templates, 1)
  }

  # Generate the dataset
  data_list <- list()

  for (i in 1:size) {
    # Select random components
    estado <- sample(estados, 1)
    categoria <- sample(categorias, 1)
    modal <- sample(modais, 1)
    tipo <- sample(tipos, 1)
    keyword <- sample(transport_keywords, 1)
    jurisdicao <- sample(jurisdicoes, 1)
    autoridade <- sample(autoridades, 1)

    # Generate year (weighted towards recent years)
    ano <- sample(2020:2025, 1, prob = c(0.1, 0.15, 0.2, 0.25, 0.25, 0.05))

    # Generate number
    numero <- sample(1:9999, 1)

    # Generate date
    mes <- sample(1:12, 1)
    dia <- sample(1:28, 1)
    data <- sprintf("%04d-%02d-%02d", ano, mes, dia)

    # Generate title
    titulo <- generate_title(tipo, keyword, ano, numero)

    # Generate URN
    if (estado == "Federal") {
      urn <- paste0("urn:lex:br:federal:", tolower(gsub(" ", ".", tipo)), ":", data, ";", numero)
    } else {
      urn <- paste0("urn:lex:br;", tolower(estado), ":", tolower(gsub(" ", ".", tipo)), ":", data, ";", numero)
    }

    # Generate ementa
    ementa <- generate_ementa(keyword, modal, categoria)

    # Generate URL
    url <- paste0("https://www.lexml.gov.br/urn/", gsub(":", "/", urn))

    # Create document entry
    doc <- data.frame(
      titulo = titulo,
      tipo = tipo,
      data = data,
      urn = urn,
      autor = autoridade,
      assuntos = toupper(paste(sample(transport_keywords, 3), collapse = ", ")),
      classificacao = "",
      jurisdicao = jurisdicao,
      autoridade = autoridade,
      ementa = ementa,
      url = url,
      localidade = "",
      numero = as.character(numero),
      ano = as.character(ano),
      termo_busca = keyword,
      data_coleta = "2025-07-22 00:37:06",
      origem = "emergency_generator",
      categoria = categoria,
      modal = modal,
      pais = "Brasil",
      estado = if (estado == "Federal") "Federal" else estado,
      municipio = "",
      fontes_localizacao = if (estado == "Federal") "jurisdicao_federal" else "urn_estado_nome",
      `_source_file` = "emergency_dataset.R",
      `_extracted_category` = categoria,
      `_extracted_transport_mode` = modal,
      `_deduplication_source` = "emergency",
      `_original_count` = "1",
      `_merged_categories` = "",
      `_merged_transport` = "",
      stringsAsFactors = FALSE
    )

    data_list[[i]] <- doc
  }

  # Combine all documents
  emergency_data <- do.call(rbind, data_list)

  # Add some variation in state distribution
  federal_indices <- sample(1:nrow(emergency_data), size = round(nrow(emergency_data) * 0.3))
  sp_indices <- sample(setdiff(1:nrow(emergency_data), federal_indices), size = round(nrow(emergency_data) * 0.2))

  emergency_data$estado[federal_indices] <- "Federal"
  emergency_data$estado[sp_indices] <- "SP"

  cat("✅ Emergency dataset generated successfully!\n")
  cat("   - Total documents:", nrow(emergency_data), "\n")
  cat("   - Categories:", paste(table(emergency_data$categoria), collapse = ", "), "\n")
  cat("   - Transport modes:", paste(names(table(emergency_data$modal)), collapse = ", "), "\n")
  cat("   - States represented:", length(unique(emergency_data$estado)), "\n")
  cat("   - Year range:", min(emergency_data$ano), "-", max(emergency_data$ano), "\n")

  return(emergency_data)
}

#' Get Emergency Data
#' Returns the emergency dataset, generating it if needed
get_emergency_data <- function() {
  if (!exists(".emergency_dataset_cache")) {
    cat("Creating emergency dataset cache...\n")
    .emergency_dataset_cache <<- generate_emergency_dataset(500)
  }
  return(.emergency_dataset_cache)
}

#' Emergency Analytics Data Function
#' Replacement for analytics_data when CSV files are missing
emergency_analytics_data <- function() {
  tryCatch({
    data <- get_emergency_data()
    cat("✅ Emergency analytics data loaded:", nrow(data), "documents\n")
    return(data)
  }, error = function(e) {
    cat("❌ Emergency analytics data failed:", e$message, "\n")
    # Return minimal fallback data
    return(data.frame(
      titulo = "Fallback Document",
      categoria = "Legislação",
      modal = "geral",
      estado = "SP",
      ano = "2025",
      data = "2025-01-01",
      stringsAsFactors = FALSE
    ))
  })
}

#' Emergency Library Documents Function
#' Replacement for get_library_documents when database is unavailable
emergency_get_library_documents <- function(limit = 100, offset = 0, categoria = NULL, modal = NULL, estado = NULL, ano = NULL) {
  tryCatch({
    data <- get_emergency_data()

    # Apply filters if provided
    if (!is.null(categoria)) {
      data <- data[data$categoria %in% categoria, ]
    }
    if (!is.null(modal)) {
      data <- data[data$modal %in% modal, ]
    }
    if (!is.null(estado)) {
      data <- data[data$estado %in% estado, ]
    }
    if (!is.null(ano)) {
      data <- data[data$ano %in% ano, ]
    }

    # Apply pagination
    start_idx <- offset + 1
    end_idx <- min(offset + limit, nrow(data))

    if (start_idx <= nrow(data)) {
      result <- data[start_idx:end_idx, ]
      cat("✅ Emergency library documents:", nrow(result), "documents returned\n")
      return(result)
    } else {
      cat("⚠️ No documents available for requested page\n")
      return(data.frame())
    }
  }, error = function(e) {
    cat("❌ Emergency library documents failed:", e$message, "\n")
    return(data.frame())
  })
}

# Global assignment for compatibility
get_library_documents_emergency <<- emergency_get_library_documents
analytics_data_emergency <<- emergency_analytics_data

cat("========================================\n")
cat("🏁 EMERGENCY DATASET SYSTEM READY\n")
cat("========================================\n")
cat("Available functions:\n")
cat("- generate_emergency_dataset(size)\n")
cat("- get_emergency_data()\n")
cat("- emergency_analytics_data()\n")
cat("- emergency_get_library_documents(...)\n")
cat("========================================\n")