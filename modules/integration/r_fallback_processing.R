# ============================================================================
# R FALLBACK PROCESSING - Monitor Legislativo v4
# Processamento de Fallback em R Puro
# ============================================================================

library(stringr)
library(dplyr)
library(tm)
library(SnowballC)

# Configuração do processamento de fallback
FALLBACK_CONFIG <- list(
  min_confidence = 0.3,
  max_processing_time = 30,
  enable_caching = TRUE,
  cache_duration = 3600
)

# Cache para resultados de fallback
if (!exists(".fallback_cache", envir = .GlobalEnv)) {
  assign(".fallback_cache", list(), envir = .GlobalEnv)
}

#' Análise de sentimento em R puro
#' @param text Texto para analisar
#' @param language Idioma (pt, en)
analyze_sentiment_fallback <- function(text, language = "pt") {
  cache_key <- paste0("sentiment_", digest::digest(text))
  
  # Verificar cache
  if (FALLBACK_CONFIG$enable_caching && exists(cache_key, envir = .GlobalEnv)) {
    cached_result <- get(cache_key, envir = .GlobalEnv)
    if (Sys.time() - cached_result$timestamp < FALLBACK_CONFIG$cache_duration) {
      return(cached_result$result)
    }
  }
  
  # Dicionários de sentimento em português
  positive_words <- c(
    "bom", "ótimo", "excelente", "positivo", "benefício", "vantagem",
    "melhor", "superior", "eficiente", "efetivo", "sucesso", "progresso",
    "desenvolvimento", "crescimento", "melhoria", "avanço", "inovação",
    "qualidade", "confiança", "segurança", "estabilidade", "prosperidade"
  )
  
  negative_words <- c(
    "ruim", "péssimo", "negativo", "problema", "dificuldade", "obstáculo",
    "pior", "inferior", "ineficiente", "inefetivo", "fracasso", "regresso",
    "declínio", "decadência", "deterioração", "retrocesso", "estagnação",
    "baixa", "desconfiança", "insegurança", "instabilidade", "crise"
  )
  
  # Limpar e preparar texto
  text_clean <- tolower(text)
  text_clean <- str_remove_all(text_clean, "[^a-záêôãç ]")
  text_clean <- str_squish(text_clean)
  
  # Contar palavras positivas e negativas
  words <- str_split(text_clean, " ")[[1]]
  words <- words[words != ""]
  
  positive_count <- sum(words %in% positive_words)
  negative_count <- sum(words %in% negative_words)
  total_words <- length(words)
  
  # Calcular sentimento
  if (total_words == 0) {
    sentiment <- "neutral"
    confidence <- 0.5
  } else {
    positive_ratio <- positive_count / total_words
    negative_ratio <- negative_count / total_words
    
    if (positive_ratio > negative_ratio) {
      sentiment <- "positive"
      confidence <- min(0.9, 0.5 + (positive_ratio - negative_ratio) * 2)
    } else if (negative_ratio > positive_ratio) {
      sentiment <- "negative"
      confidence <- min(0.9, 0.5 + (negative_ratio - positive_ratio) * 2)
    } else {
      sentiment <- "neutral"
      confidence <- 0.5
    }
  }
  
  result <- list(
    sentiment = sentiment,
    confidence = max(FALLBACK_CONFIG$min_confidence, confidence),
    positive_count = positive_count,
    negative_count = negative_count,
    total_words = total_words,
    method = "r_fallback"
  )
  
  # Salvar no cache
  if (FALLBACK_CONFIG$enable_caching) {
    assign(cache_key, list(
      result = result,
      timestamp = Sys.time()
    ), envir = .GlobalEnv)
  }
  
  return(result)
}

#' Classificação de documentos em R puro
#' @param title Título do documento
#' @param content Conteúdo do documento
classify_document_fallback <- function(title, content) {
  cache_key <- paste0("classify_", digest::digest(paste(title, content)))
  
  # Verificar cache
  if (FALLBACK_CONFIG$enable_caching && exists(cache_key, envir = .GlobalEnv)) {
    cached_result <- get(cache_key, envir = .GlobalEnv)
    if (Sys.time() - cached_result$timestamp < FALLBACK_CONFIG$cache_duration) {
      return(cached_result$result)
    }
  }
  
  # Padrões para classificação
  patterns <- list(
    legislacao = c("lei", "decreto", "portaria", "resolução", "instrução normativa"),
    jurisprudencia = c("acórdão", "decisão", "sentença", "julgamento", "precedente"),
    administrativo = c("ato administrativo", "procedimento", "processo administrativo"),
    constitucional = c("emenda constitucional", "adc", "adpf", "adc"),
    penal = c("código penal", "lei penal", "crime", "delito"),
    civil = c("código civil", "direito civil", "contrato", "obrigação"),
    tributario = c("código tributário", "imposto", "tributo", "fiscal")
  )
  
  # Combinar título e conteúdo
  full_text <- paste(title, content)
  full_text <- tolower(full_text)
  
  # Calcular scores para cada categoria
  scores <- sapply(patterns, function(pattern_words) {
    sum(sapply(pattern_words, function(word) {
      length(grep(word, full_text, ignore.case = TRUE))
    }))
  })
  
  # Determinar categoria principal
  if (max(scores) == 0) {
    doc_type <- "outros"
    confidence <- 0.3
  } else {
    doc_type <- names(which.max(scores))
    confidence <- min(0.9, 0.5 + (max(scores) / length(full_text)) * 100)
  }
  
  result <- list(
    type = doc_type,
    confidence = max(FALLBACK_CONFIG$min_confidence, confidence),
    scores = scores,
    method = "r_fallback"
  )
  
  # Salvar no cache
  if (FALLBACK_CONFIG$enable_caching) {
    assign(cache_key, list(
      result = result,
      timestamp = Sys.time()
    ), envir = .GlobalEnv)
  }
  
  return(result)
}

#' Extração de entidades em R puro
#' @param text Texto para extrair entidades
extract_entities_fallback <- function(text) {
  cache_key <- paste0("entities_", digest::digest(text))
  
  # Verificar cache
  if (FALLBACK_CONFIG$enable_caching && exists(cache_key, envir = .GlobalEnv)) {
    cached_result <- get(cache_key, envir = .GlobalEnv)
    if (Sys.time() - cached_result$timestamp < FALLBACK_CONFIG$cache_duration) {
      return(cached_result$result)
    }
  }
  
  # Padrões para extração de entidades
  patterns <- list(
    # Pessoas (nomes próprios com maiúscula)
    person = "\\b[A-ZÁÊÔÃÇ][a-záêôãç]+\\s+[A-ZÁÊÔÃÇ][a-záêôãç]+\\b",
    
    # Organizações
    organization = "\\b[A-ZÁÊÔÃÇ][A-Za-záêôãç\\s]+(?:Ministério|Secretaria|Departamento|Instituto|Fundacao|Conselho|Tribunal|Corte|Supremo|Superior)\\b",
    
    # Localizações
    location = "\\b(?:Brasil|Brasília|São Paulo|Rio de Janeiro|Minas Gerais|Bahia|Paraná|Rio Grande do Sul|Pernambuco|Ceará|Pará|Maranhão|Santa Catarina|Goiás|Paraíba|Espírito Santo|Piauí|Alagoas|Tocantins|Rondônia|Acre|Amapá|Roraima|Distrito Federal)\\b",
    
    # Datas
    date = "\\b(?:0?[1-9]|[12][0-9]|3[01])/(?:0?[1-9]|1[0-2])/(?:19|20)\\d{2}\\b",
    
    # Leis e decretos
    legal_document = "\\b(?:Lei|Decreto|Portaria|Resolução)\\s+(?:n[oº]\\s*)?\\d+(?:/\\d{4})?\\b",
    
    # Valores monetários
    money = "\\bR\\$\\s*\\d+(?:[.,]\\d{3})*(?:[.,]\\d{2})?\\b"
  )
  
  entities <- list()
  
  for (entity_type in names(patterns)) {
    matches <- str_extract_all(text, patterns[[entity_type]], ignore.case = TRUE)
    entities[[entity_type]] <- unique(unlist(matches))
  }
  
  # Filtrar entidades vazias
  entities <- entities[sapply(entities, length) > 0]
  
  result <- list(
    entities = entities,
    total_entities = sum(sapply(entities, length)),
    confidence = 0.4, # Confiança menor para fallback
    method = "r_fallback"
  )
  
  # Salvar no cache
  if (FALLBACK_CONFIG$enable_caching) {
    assign(cache_key, list(
      result = result,
      timestamp = Sys.time()
    ), envir = .GlobalEnv)
  }
  
  return(result)
}

#' Análise de tópicos em R puro
#' @param texts Vetor de textos
#' @param n_topics Número de tópicos
analyze_topics_fallback <- function(texts, n_topics = 5) {
  if (length(texts) < 2) {
    return(list(
      topics = list(),
      confidence = 0.3,
      method = "r_fallback"
    ))
  }
  
  # Preparar corpus
  corpus <- Corpus(VectorSource(texts))
  corpus <- tm_map(corpus, content_transformer(tolower))
  corpus <- tm_map(corpus, removePunctuation)
  corpus <- tm_map(corpus, removeNumbers)
  corpus <- tm_map(corpus, removeWords, stopwords("portuguese"))
  corpus <- tm_map(corpus, stemDocument, language = "portuguese")
  corpus <- tm_map(corpus, stripWhitespace)
  
  # Criar matriz termo-documento
  dtm <- DocumentTermMatrix(corpus)
  
  # Análise básica de frequência
  freq_terms <- findFreqTerms(dtm, lowfreq = 2)
  
  if (length(freq_terms) == 0) {
    return(list(
      topics = list(),
      confidence = 0.3,
      method = "r_fallback"
    ))
  }
  
  # Agrupar termos por similaridade básica
  topics <- list()
  terms_per_topic <- max(1, length(freq_terms) %/% n_topics)
  
  for (i in 1:n_topics) {
    start_idx <- (i - 1) * terms_per_topic + 1
    end_idx <- min(i * terms_per_topic, length(freq_terms))
    
    if (start_idx <= length(freq_terms)) {
      topics[[paste0("topic_", i)]] <- freq_terms[start_idx:end_idx]
    }
  }
  
  result <- list(
    topics = topics,
    n_topics = length(topics),
    confidence = 0.4,
    method = "r_fallback"
  )
  
  return(result)
}

#' Processamento de texto completo em R puro
#' @param text Texto para processar
process_text_fallback <- function(text) {
  start_time <- Sys.time()
  
  # Verificar timeout
  if (as.numeric(Sys.time() - start_time) > FALLBACK_CONFIG$max_processing_time) {
    return(list(
      error = "Timeout no processamento",
      method = "r_fallback"
    ))
  }
  
  # Executar todas as análises
  sentiment <- analyze_sentiment_fallback(text)
  classification <- classify_document_fallback(text, text)
  entities <- extract_entities_fallback(text)
  
  result <- list(
    sentiment = sentiment,
    classification = classification,
    entities = entities,
    processing_time = as.numeric(Sys.time() - start_time),
    method = "r_fallback"
  )
  
  return(result)
}

#' Limpar cache de fallback
clear_fallback_cache <- function() {
  if (exists(".fallback_cache", envir = .GlobalEnv)) {
    rm(".fallback_cache", envir = .GlobalEnv)
    assign(".fallback_cache", list(), envir = .GlobalEnv)
    cat("🧹 Cache de fallback limpo\n")
  }
}

#' Obter estatísticas do cache de fallback
get_fallback_cache_stats <- function() {
  if (!exists(".fallback_cache", envir = .GlobalEnv)) {
    return(list(size = 0, entries = 0))
  }
  
  cache <- get(".fallback_cache", envir = .GlobalEnv)
  
  return(list(
    size = length(cache),
    entries = names(cache),
    memory_usage = object.size(cache)
  ))
}

# Exportar funções para uso global
assign("analyze_sentiment_fallback", analyze_sentiment_fallback, envir = .GlobalEnv)
assign("classify_document_fallback", classify_document_fallback, envir = .GlobalEnv)
assign("extract_entities_fallback", extract_entities_fallback, envir = .GlobalEnv)
assign("analyze_topics_fallback", analyze_topics_fallback, envir = .GlobalEnv)
assign("process_text_fallback", process_text_fallback, envir = .GlobalEnv)
assign("clear_fallback_cache", clear_fallback_cache, envir = .GlobalEnv)
assign("get_fallback_cache_stats", get_fallback_cache_stats, envir = .GlobalEnv)

cat("✅ Sistema de Fallback R carregado e disponível globalmente\n")
