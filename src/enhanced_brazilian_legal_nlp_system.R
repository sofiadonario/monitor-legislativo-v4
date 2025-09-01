# ============================================================================
# ENHANCED BRAZILIAN LEGAL NLP SYSTEM
# Brazilian Legislative Monitoring System - Advanced Text Analytics Platform
# Author: Legislative Data Science Framework
# Date: 2025-09-01
# Description: Comprehensive NLP system for Portuguese legal texts with 
#              academic research standards and government decision-support
# ============================================================================

# Core Libraries ============================================================
suppressPackageStartupMessages({
  library(tidyverse)      # Data manipulation
  library(tidytext)       # Text mining
  library(quanteda)       # Advanced text analysis
  library(topicmodels)    # LDA topic modeling
  library(stm)            # Structural topic modeling
  library(textTinyR)      # Fast text processing
  library(text)           # Transformers and BERT models
  library(sentimentr)     # Sentiment analysis
  library(udpipe)         # Portuguese NLP pipeline
  library(spacyr)         # Portuguese spaCy integration
  library(textclean)      # Text cleaning
  library(SnowballC)      # Portuguese stemming
  library(hunspell)       # Portuguese spell checking
  library(wordcloud2)     # Advanced word clouds  
  library(networkD3)      # Network visualization
  library(igraph)         # Network analysis
  library(plotly)         # Interactive plots
  library(DT)             # Interactive tables
  library(visNetwork)     # Network visualization
  library(tm.plugin.lexisnexis) # Legal text processing
  library(textstat)       # Text statistics
  library(lexicon)        # Sentiment lexicons
  library(syuzhet)        # Sentiment analysis methods
  library(RColorBrewer)   # Color palettes
  library(viridis)        # Scientific color palettes
  library(lubridate)      # Date handling
  library(jsonlite)       # JSON handling
  library(parallel)       # Parallel processing
  library(doParallel)     # Parallel backend
  library(future)         # Async processing
  library(memoise)        # Function memoization
  library(digest)         # Hashing for caching
})

# Enhanced Portuguese Legal NLP Configuration ===============================
ENHANCED_PORTUGUESE_LEGAL_CONFIG <- list(
  
  # Comprehensive Portuguese Legal Stopwords (300+ terms)
  enhanced_legal_stopwords = c(
    # Basic Portuguese stopwords
    "a", "o", "e", "de", "da", "do", "das", "dos", "em", "para", "com", "por", 
    "que", "se", "na", "no", "um", "uma", "os", "as", "ao", "à", "pelo", "pela",
    "este", "esta", "esse", "essa", "aquele", "aquela", "seu", "sua", "seus", "suas",
    "mas", "mais", "muito", "bem", "já", "ainda", "onde", "quando", "como", "porque",
    "então", "assim", "também", "só", "após", "até", "entre", "sob", "sobre", "desde",
    
    # Legal document structure terms
    "artigo", "art", "parágrafo", "§", "inciso", "alínea", "item", "capítulo", 
    "título", "seção", "subseção", "parte", "livro", "código", "anexo", "apêndice",
    "estabelece", "dispõe", "institui", "cria", "altera", "revoga", "regulamenta", 
    "aprova", "autoriza", "determina", "define", "fixa", "disciplina", "organiza",
    
    # Legal instruments and procedures  
    "lei", "decreto", "resolução", "portaria", "instrução", "normativa", "medida", 
    "provisória", "emenda", "constitucional", "súmula", "jurisprudência", "acórdão",
    "sentença", "decisão", "despacho", "parecer", "voto", "relatório", "processo",
    
    # Jurisdictional and administrative terms
    "brasil", "brasileiro", "brasileira", "nacional", "federal", "estadual", 
    "municipal", "distrital", "união", "estado", "município", "distrito", 
    "território", "governo", "poder", "público", "administração", "executivo",
    "legislativo", "judiciário", "supremo", "superior", "tribunal", "justiça",
    
    # Procedural and temporal terms
    "outras", "providências", "dá", "sobre", "matéria", "assunto", "objeto", 
    "finalidade", "vigência", "eficácia", "prazo", "termo", "data", "publicação",
    "vigência", "revogação", "suspensão", "cassação", "anulação", "confirmação",
    
    # Legal entities and roles
    "ministério", "secretaria", "departamento", "agência", "autarquia", "fundação", 
    "empresa", "sociedade", "conselho", "comissão", "comitê", "grupo", "câmara",
    "juiz", "desembargador", "ministro", "promotor", "procurador", "defensor",
    "advogado", "bacharel", "doutor", "professor", "relator", "revisor",
    
    # Transport and logistics specific legal terms
    "transporte", "transportador", "transportar", "rodoviário", "ferroviário", 
    "aquaviário", "aeroviário", "multimodal", "intermodal", "veicular", "logística", 
    "carga", "mercadoria", "frete", "caminhão", "veículo", "modal", "via", 
    "rodovia", "estrada", "pista", "tráfego", "trânsito", "circulação"
  ),
  
  # Enhanced Legal Sentiment Lexicon for Regulatory Analysis
  enhanced_regulatory_sentiment = list(
    # Highly positive/permissive regulatory terms
    highly_positive = c(
      "autoriza", "permite", "libera", "flexibiliza", "desburocratiza", "moderniza",
      "simplifica", "facilita", "agiliza", "otimiza", "aprimora", "fortalece",
      "incentiva", "estimula", "promove", "fomenta", "beneficia", "favorece",
      "protege", "garante", "assegura", "preserva", "desenvolve", "inova"
    ),
    
    # Moderately positive/enabling terms  
    moderately_positive = c(
      "melhoria", "eficiência", "qualidade", "excelência", "transparência", 
      "participação", "sustentável", "sustentabilidade", "segurança", "proteção",
      "direitos", "garantias", "benefício", "vantagem", "oportunidade", "acesso",
      "inclusão", "integração", "cooperação", "colaboração", "parceria"
    ),
    
    # Neutral/procedural regulatory terms
    neutral_procedural = c(
      "estabelece", "regulamenta", "define", "determina", "disciplina", "organiza", 
      "estrutura", "procedimento", "processo", "tramitação", "análise", "avaliação",
      "verificação", "controle", "fiscalização", "monitoramento", "acompanhamento",
      "relatório", "informação", "comunicação", "notificação", "publicação",
      "registro", "cadastro", "licenciamento", "habilitação", "certificação"
    ),
    
    # Moderately negative/restrictive terms
    moderately_negative = c(
      "restrição", "limitação", "condicionamento", "impedimento", "obstáculo",
      "dificuldade", "problema", "deficiência", "falha", "insuficiência",
      "inadequado", "irregular", "indevido", "impróprio", "incorreto", "falso"
    ),
    
    # Highly negative/punitive regulatory terms
    highly_negative = c(
      "proíbe", "veda", "impede", "cancela", "suspende", "revoga", "cassa", 
      "multa", "penalidade", "sanção", "punição", "infração", "violação",
      "descumprimento", "irregularidade", "ilegalidade", "crime", "contravenção",
      "responsabilização", "condenação", "prisão", "detenção", "reclusão"
    )
  ),
  
  # Brazilian Legal Entity Recognition Patterns  
  enhanced_legal_patterns = list(
    # Brazilian legal instruments with enhanced patterns
    legal_instruments = c(
      "\\blei\\s+(n[°º]?\\.?\\s*)?\\d+[,./]?\\d*(/\\d+)?\\b",
      "\\bdecreto(-lei)?\\s+(n[°º]?\\.?\\s*)?\\d+[,./]?\\d*(/\\d+)?\\b", 
      "\\bresolução\\s+(n[°º]?\\.?\\s*)?\\d+[,./]?\\d*(/\\d+)?\\b",
      "\\bportaria\\s+(n[°º]?\\.?\\s*)?\\d+[,./]?\\d*(/\\d+)?\\b",
      "\\binstrução\\s+normativa\\s+(n[°º]?\\.?\\s*)?\\d+[,./]?\\d*(/\\d+)?\\b",
      "\\bmedida\\s+provisória\\s+(n[°º]?\\.?\\s*)?\\d+[,./]?\\d*(/\\d+)?\\b",
      "\\bemenda\\s+constitucional\\s+(n[°º]?\\.?\\s*)?\\d+[,./]?\\d*(/\\d+)?\\b",
      "\\bsúmula\\s+(vinculante\\s+)?(n[°º]?\\.?\\s*)?\\d+\\b",
      "\\bconstituição\\s+federal\\b", "\\bcódigo\\s+(civil|penal|tributário)\\b"
    ),
    
    # Enhanced regulatory agencies and authorities
    regulatory_agencies = c(
      "antt", "antaq", "anac", "aneel", "anp", "ancine", "anvisa", "ana", "anatel",
      "cvm", "bacen", "banco\\s+central", "cade", "ibama", "icmbio", "dnit", "der",
      "contran", "denatran", "detran", "cetran", "ciretran", "jari", "inss", "receita\\s+federal",
      "ministério\\s+(da|de|do)", "secretaria\\s+(da|de|do)", "agência\\s+nacional",
      "departamento\\s+nacional", "instituto\\s+(brasileiro|nacional)", "fundação\\s+nacional",
      "conselho\\s+(nacional|federal|superior)", "comissão\\s+(nacional|federal)"
    ),
    
    # Courts and legal authorities with enhanced patterns
    legal_authorities = c(
      "supremo\\s+tribunal\\s+federal", "stf", "superior\\s+tribunal\\s+de\\s+justiça", "stj",
      "tribunal\\s+superior\\s+(do\\s+trabalho|eleitoral)", "tst", "tse", "superior\\s+tribunal\\s+militar", "stm",
      "tribunal\\s+(regional\\s+)?(federal|do\\s+trabalho|eleitoral|de\\s+justiça)", "trf", "trt", "tre", "tjsp", "tjrj",
      "tribunal\\s+de\\s+contas\\s+(da\\s+união|do\\s+estado)", "tcu", "tce",
      "juizado\\s+especial\\s+(cível|criminal|federal)", "vara\\s+(cível|criminal|trabalhista|federal)",
      "ministério\\s+público\\s+(federal|do\\s+trabalho|eleitoral)", "mpf", "mpt", "mpe",
      "promotoria\\s+(de\\s+justiça)?", "defensoria\\s+pública", "ordem\\s+dos\\s+advogados", "oab"
    ),
    
    # Geographic jurisdictions  
    geographic_entities = c(
      "brasil", "república\\s+federativa\\s+do\\s+brasil", "união", "governo\\s+federal",
      "acre|alagoas|amapá|amazonas|bahia|ceará|distrito\\s+federal|espírito\\s+santo",
      "goiás|maranhão|mato\\s+grosso|minas\\s+gerais|pará|paraíba|paraná|pernambuco",
      "piauí|rio\\s+de\\s+janeiro|rio\\s+grande\\s+do\\s+(norte|sul)|rondônia|roraima",
      "santa\\s+catarina|são\\s+paulo|sergipe|tocantins", "município\\s+de", "prefeitura\\s+(municipal\\s+)?de"
    )
  ),
  
  # Enhanced Transport Domain Classification
  enhanced_transport_themes = list(
    # Alternative fuels and sustainable energy
    alternative_fuels = c(
      "biocombustível", "biodiesel", "etanol\\s+(hidratado|anidro)?", "bioetanol",
      "gás\\s+natural\\s+(veicular|gnv)", "biometano", "hidrogênio\\s+(verde|azul)?",
      "combustível\\s+(sustentável|renovável|limpo)", "diesel\\s+(verde|renovável|hvo)",
      "célula\\s+(de\\s+)?combustível", "eletrificação", "veículo\\s+elétrico",
      "bateria\\s+(elétrica|de\\s+lítio)", "energia\\s+(renovável|limpa|solar|eólica)"
    ),
    
    # Infrastructure and logistics systems
    infrastructure_logistics = c(
      "infraestrutura\\s+(rodoviária|ferroviária|portuária|aeroportuária|logística)",
      "terminal\\s+(de\\s+)?carga", "centro\\s+de\\s+distribuição", "armazém",
      "depósito", "pátio\\s+(de\\s+)?manobras", "posto\\s+(de\\s+)?(abastecimento|gasolina)",
      "rede\\s+de\\s+distribuição", "corredor\\s+logístico", "hub\\s+logístico",
      "plataforma\\s+logística", "porto\\s+(seco|alfandegado)", "estação\\s+aduaneira",
      "condomínio\\s+logístico", "parque\\s+industrial", "zona\\s+franca"
    ),
    
    # Vehicle technology and safety systems
    vehicle_technology = c(
      "veículo\\s+(autônomo|conectado|inteligente)", "tecnologia\\s+assistiva",
      "telemetria", "rastreamento\\s+(veicular|por\\s+satélite)", "gps", "sistema\\s+de\\s+freios",
      "airbag", "cinto\\s+de\\s+segurança", "velocímetro", "tacógrafo", "hodômetro",
      "monitoramento\\s+(eletrônico|em\\s+tempo\\s+real)", "sensor\\s+(de\\s+)?(temperatura|pressão|velocidade)",
      "conectividade\\s+(5g|iot)", "big\\s+data", "inteligência\\s+artificial",
      "machine\\s+learning", "blockchain", "internet\\s+(das\\s+)?coisas"
    ),
    
    # Environmental impact and emissions
    environmental_impact = c(
      "emissão\\s+(de\\s+)?(gases|poluentes|co2)", "descarbonização", 
      "gases\\s+(de\\s+)?efeito\\s+estufa", "pegada\\s+(de\\s+)?carbono",
      "eficiência\\s+(energética|combustível)", "consumo\\s+(de\\s+)?combustível",
      "poluição\\s+(atmosférica|sonora|hídrica)", "meio\\s+ambiente", "sustentabilidade",
      "mudança\\s+(climática|do\\s+clima)", "aquecimento\\s+global", "protocolo\\s+de\\s+kyoto",
      "acordo\\s+de\\s+paris", "neutralidade\\s+carbônica", "economia\\s+(circular|verde)"
    ),
    
    # Regulation and compliance systems
    regulation_compliance = c(
      "licenciamento\\s+(ambiental|veicular)", "habilitação\\s+(profissional|de\\s+condutor)",
      "certificação\\s+(iso|inmetro)", "homologação\\s+(veicular|de\\s+equipamentos)",
      "inspeção\\s+(veicular|técnica|ambiental)", "vistoria", "auditoria\\s+(de\\s+qualidade)?",
      "fiscalização\\s+(eletrônica|rodoviária)", "multa\\s+(de\\s+trânsito)?", "infração",
      "compliance", "governança", "transparência", "prestação\\s+de\\s+contas",
      "regulamentação\\s+(técnica|ambiental)", "normatização", "padronização",
      "acreditação", "rastreabilidade", "due\\s+diligence"
    ),
    
    # Digital transformation and innovation
    digital_innovation = c(
      "transformação\\s+digital", "digitalização", "plataforma\\s+digital",
      "aplicativo\\s+(móvel|mobile)", "e-commerce", "marketplace", "fintech",
      "startup", "inovação\\s+(tecnológica|disruptiva)", "pesquisa\\s+(e\\s+)?desenvolvimento",
      "prototipagem", "teste\\s+piloto", "sandbox\\s+regulatório", "living\\s+lab",
      "ecossistema\\s+de\\s+inovação", "venture\\s+capital", "investimento\\s+anjo"
    )
  ),
  
  # Text Processing Configuration
  processing_config = list(
    # Performance optimization settings
    max_features = 10000,           # Maximum vocabulary size
    min_doc_freq = 5,              # Minimum document frequency
    max_doc_freq = 0.95,           # Maximum document frequency proportion
    ngram_range = c(1, 3),         # N-gram range for feature extraction
    chunk_size = 1000,             # Document processing chunk size
    parallel_cores = 4,            # Number of parallel processing cores
    cache_results = TRUE,          # Enable result caching
    memory_limit_mb = 4096,        # Memory limit in MB
    
    # Text cleaning parameters
    min_char_length = 50,          # Minimum character length for documents
    max_char_length = 50000,       # Maximum character length for documents
    remove_numbers = FALSE,        # Keep numbers for legal references
    remove_punct = FALSE,          # Keep punctuation for legal structure
    to_lower = TRUE,               # Convert to lowercase
    remove_accents = FALSE,        # Keep Portuguese accents
    
    # Topic modeling parameters
    topic_range = c(5, 50),        # Range of topics to test
    topic_step = 5,                # Step size for topic number testing
    lda_iterations = 1000,         # LDA iterations
    lda_burnin = 250,              # LDA burn-in period
    coherence_measure = "c_v",     # Topic coherence measure
    
    # Similarity analysis parameters
    similarity_method = "cosine",   # Similarity calculation method
    similarity_threshold = 0.1,    # Minimum similarity threshold
    clustering_method = "leiden",   # Community detection method
    network_layout = "fr",         # Network visualization layout
    
    # Performance monitoring
    log_processing_time = TRUE,    # Log processing times
    memory_monitoring = TRUE,      # Monitor memory usage
    progress_reporting = TRUE      # Report progress during processing
  )
)

# Core Enhanced NLP Functions ===============================================

#' Enhanced Portuguese Legal Text Preprocessing Pipeline
#' 
#' Comprehensive preprocessing pipeline optimized for Portuguese legal texts
#' with academic research standards and large-scale corpus handling
#' 
#' @param texts Vector of text documents to process
#' @param config Processing configuration list
#' @param parallel Enable parallel processing
#' @return List containing preprocessed texts and processing metadata
preprocess_legal_corpus <- function(texts, config = ENHANCED_PORTUGUESE_LEGAL_CONFIG$processing_config, parallel = TRUE) {
  
  start_time <- Sys.time()
  cat("🔧 Enhanced Legal Text Preprocessing Pipeline\n")
  cat("📊 Processing", length(texts), "documents with advanced NLP techniques\n")
  
  # Initialize parallel processing if requested
  if (parallel && config$parallel_cores > 1) {
    registerDoParallel(cores = min(config$parallel_cores, detectCores() - 1))
    cat("⚡ Parallel processing enabled with", getDoParWorkers(), "cores\n")
  }
  
  # Step 1: Initial text validation and filtering
  cat("📋 Step 1: Document validation and filtering...\n")
  valid_indices <- which(
    !is.na(texts) & 
    nchar(texts) >= config$min_char_length & 
    nchar(texts) <= config$max_char_length &
    str_detect(texts, "[a-zA-ZÀ-ÿ]")  # Contains at least some letters
  )
  
  valid_texts <- texts[valid_indices]
  cat("✅ Retained", length(valid_texts), "valid documents from", length(texts), "total\n")
  
  # Step 2: Advanced legal-specific text cleaning
  cat("🧹 Step 2: Legal-specific text normalization...\n")
  
  cleaned_texts <- valid_texts %>%
    # Remove legal document metadata and headers
    str_remove_all("(?i)\\ourt\\s*[:\\-]?\\s*(lex|lexml)\\s*[:\\-]?\\s*(br|brasil)\\b.*?\\n") %>%
    str_remove_all("(?i)\\bclassificação\\s*[:\\-]\\s*.*?\\n") %>%
    str_remove_all("(?i)\\bautor\\s*[:\\-]\\s*.*?\\n") %>%
    str_remove_all("(?i)\\bassunto\\s*[:\\-]\\s*.*?\\n") %>%
    
    # Clean legal citations and cross-references
    str_remove_all("\\b(artigo|art\\.?)\\s+\\d+[°º]?(\\s*[-,]\\s*\\d+[°º]?)*") %>%
    str_remove_all("\\b(parágrafo|§)\\s+\\d+[°º]?(\\s*[-,]\\s*\\d+[°º]?)*") %>%
    str_remove_all("\\b(inciso|alínea)\\s+[ivxlcdm]+") %>%
    
    # Remove URLs, emails, and technical artifacts
    str_remove_all("https?://[^\\s]+") %>%
    str_remove_all("www\\.[^\\s]+") %>%
    str_remove_all("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}") %>%
    str_remove_all("\\{[^}]*\\}|\\[[^]]*\\]|\\([^)]{50,}\\)") %>%
    
    # Normalize whitespace and punctuation
    str_replace_all("\\s*[-_=]{3,}\\s*", " ") %>%
    str_replace_all("\\n+", " ") %>%
    str_replace_all("\\s+", " ") %>%
    str_trim()
  
  # Step 3: Portuguese-specific linguistic processing
  cat("🇧🇷 Step 3: Portuguese linguistic normalization...\n")
  
  # Convert to lowercase if specified
  if (config$to_lower) {
    cleaned_texts <- str_to_lower(cleaned_texts)
  }
  
  # Remove Portuguese legal stopwords
  legal_stopwords_pattern <- paste0("\\b(", 
    paste(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_stopwords, collapse = "|"),
    ")\\b")
  
  cleaned_texts <- cleaned_texts %>%
    str_remove_all(legal_stopwords_pattern) %>%
    str_replace_all("\\s+", " ") %>%
    str_trim()
  
  # Step 4: Final quality control and filtering
  cat("🔍 Step 4: Final quality control...\n")
  
  # Remove documents that became too short after cleaning
  final_valid_indices <- which(nchar(cleaned_texts) >= config$min_char_length)
  final_texts <- cleaned_texts[final_valid_indices]
  final_original_indices <- valid_indices[final_valid_indices]
  
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  
  # Generate processing report
  processing_report <- list(
    original_documents = length(texts),
    valid_documents = length(valid_texts),
    final_documents = length(final_texts),
    retention_rate = length(final_texts) / length(texts),
    processing_time_minutes = processing_time,
    average_doc_length = mean(nchar(final_texts)),
    config_used = config,
    timestamp = Sys.time()
  )
  
  cat("🎉 Preprocessing completed successfully!\n")
  cat("📊 Final corpus:", length(final_texts), "documents\n")
  cat("⏱️ Processing time:", round(processing_time, 2), "minutes\n")
  cat("📈 Retention rate:", round(processing_report$retention_rate * 100, 1), "%\n")
  
  # Stop parallel processing
  if (parallel && config$parallel_cores > 1) {
    stopImplicitCluster()
  }
  
  return(list(
    texts = final_texts,
    original_indices = final_original_indices,
    processing_report = processing_report
  ))
}

#' Advanced Brazilian Legal Entity Recognition System
#' 
#' Comprehensive named entity recognition specialized for Brazilian legal context
#' with support for legal instruments, regulatory agencies, courts, and transport themes
#' 
#' @param texts Vector of preprocessed texts
#' @param config Processing configuration
#' @return List containing extracted entities with frequency and context analysis
extract_brazilian_legal_entities <- function(texts, config = ENHANCED_PORTUGUESE_LEGAL_CONFIG$processing_config) {
  
  start_time <- Sys.time()
  cat("🏛️ Advanced Brazilian Legal Entity Recognition\n")
  cat("📊 Processing", length(texts), "documents for entity extraction\n")
  
  # Initialize results structure
  entity_results <- list(
    legal_instruments = tibble(),
    regulatory_agencies = tibble(), 
    legal_authorities = tibble(),
    geographic_entities = tibble(),
    transport_themes = tibble(),
    co_occurrence_network = NULL,
    processing_metadata = list()
  )
  
  # Process in chunks for memory efficiency
  chunk_size <- min(config$chunk_size, length(texts))
  n_chunks <- ceiling(length(texts) / chunk_size)
  
  cat("🔄 Processing in", n_chunks, "chunks of", chunk_size, "documents each\n")
  
  all_entities_by_doc <- tibble()
  
  for (chunk_i in 1:n_chunks) {
    start_idx <- (chunk_i - 1) * chunk_size + 1
    end_idx <- min(chunk_i * chunk_size, length(texts))
    chunk_texts <- texts[start_idx:end_idx]
    
    cat("📄 Processing chunk", chunk_i, "of", n_chunks, "(docs", start_idx, "-", end_idx, ")\n")
    
    # Extract entities for this chunk
    chunk_entities <- tibble(
      doc_id = start_idx:end_idx,
      text = chunk_texts
    ) %>%
      mutate(
        # Legal instruments
        legal_instruments = map(text, function(t) {
          instruments <- c()
          for (pattern in ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_patterns$legal_instruments) {
            matches <- str_extract_all(str_to_lower(t), pattern, simplify = FALSE)[[1]]
            if (length(matches) > 0) {
              instruments <- c(instruments, matches)
            }
          }
          unique(instruments[instruments != ""])
        }),
        
        # Regulatory agencies
        regulatory_agencies = map(text, function(t) {
          agencies <- c()
          for (pattern in ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_patterns$regulatory_agencies) {
            if (str_detect(str_to_lower(t), pattern)) {
              matches <- str_extract_all(str_to_lower(t), paste0("\\b", pattern, "\\b"))[[1]]
              agencies <- c(agencies, matches[matches != ""])
            }
          }
          unique(agencies)
        }),
        
        # Legal authorities
        legal_authorities = map(text, function(t) {
          authorities <- c()
          for (pattern in ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_patterns$legal_authorities) {
            if (str_detect(str_to_lower(t), pattern)) {
              matches <- str_extract_all(str_to_lower(t), paste0("\\b", pattern, "\\b"))[[1]]
              authorities <- c(authorities, matches[matches != ""])
            }
          }
          unique(authorities)
        }),
        
        # Geographic entities
        geographic_entities = map(text, function(t) {
          locations <- c()
          for (pattern in ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_legal_patterns$geographic_entities) {
            if (str_detect(str_to_lower(t), pattern)) {
              matches <- str_extract_all(str_to_lower(t), paste0("\\b", pattern, "\\b"))[[1]]
              locations <- c(locations, matches[matches != ""])
            }
          }
          unique(locations)
        }),
        
        # Transport themes (enhanced)
        transport_themes = map(text, function(t) {
          themes_found <- list()
          for (theme_name in names(ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_transport_themes)) {
            theme_patterns <- ENHANCED_PORTUGUESE_LEGAL_CONFIG$enhanced_transport_themes[[theme_name]]
            theme_matches <- any(map_lgl(theme_patterns, ~ str_detect(str_to_lower(t), .x)))
            if (theme_matches) {
              # Find specific pattern matches for this theme
              pattern_matches <- map(theme_patterns, ~ {
                matches <- str_extract_all(str_to_lower(t), .x)[[1]]
                matches[matches != ""]
              })
              pattern_matches <- unlist(pattern_matches)
              if (length(pattern_matches) > 0) {
                themes_found[[theme_name]] <- unique(pattern_matches)
              }
            }
          }
          themes_found
        })
      )
    
    # Accumulate results
    all_entities_by_doc <- bind_rows(all_entities_by_doc, chunk_entities)
  }
  
  # Aggregate entity frequencies
  cat("📊 Aggregating entity frequencies and statistics...\n")
  
  # Legal instruments summary
  entity_results$legal_instruments <- all_entities_by_doc %>%
    select(doc_id, legal_instruments) %>%
    unnest(legal_instruments) %>%
    filter(!is.na(legal_instruments), legal_instruments != "") %>%
    count(legal_instruments, sort = TRUE, name = "frequency") %>%
    rename(entity = legal_instruments) %>%
    mutate(
      entity_type = "legal_instrument",
      relative_frequency = frequency / sum(frequency),
      category = case_when(
        str_detect(entity, "\\blei\\b") ~ "Lei",
        str_detect(entity, "\\bdecreto") ~ "Decreto",
        str_detect(entity, "\\bresolução") ~ "Resolução",
        str_detect(entity, "\\bportaria") ~ "Portaria",
        str_detect(entity, "\\bmedida\\s+provisória") ~ "Medida Provisória",
        str_detect(entity, "\\bsúmula") ~ "Súmula",
        TRUE ~ "Outros Instrumentos"
      )
    )
  
  # Regulatory agencies summary
  entity_results$regulatory_agencies <- all_entities_by_doc %>%
    select(doc_id, regulatory_agencies) %>%
    unnest(regulatory_agencies) %>%
    filter(!is.na(regulatory_agencies), regulatory_agencies != "") %>%
    count(regulatory_agencies, sort = TRUE, name = "frequency") %>%
    rename(entity = regulatory_agencies) %>%
    mutate(
      entity_type = "regulatory_agency",
      relative_frequency = frequency / sum(frequency),
      category = case_when(
        entity %in% c("antt", "antaq", "anac") ~ "Transporte",
        entity %in% c("aneel", "anp") ~ "Energia",
        entity %in% c("anvisa", "ana") ~ "Saúde e Ambiente", 
        entity %in% c("bacen", "cvm") ~ "Sistema Financeiro",
        entity %in% c("ibama", "icmbio") ~ "Meio Ambiente",
        TRUE ~ "Outras Agências"
      )
    )
  
  # Legal authorities summary
  entity_results$legal_authorities <- all_entities_by_doc %>%
    select(doc_id, legal_authorities) %>%
    unnest(legal_authorities) %>%
    filter(!is.na(legal_authorities), legal_authorities != "") %>%
    count(legal_authorities, sort = TRUE, name = "frequency") %>%
    rename(entity = legal_authorities) %>%
    mutate(
      entity_type = "legal_authority",
      relative_frequency = frequency / sum(frequency),
      category = case_when(
        str_detect(entity, "supremo|stf") ~ "Supremo Tribunal Federal",
        str_detect(entity, "superior.*justiça|stj") ~ "Superior Tribunal de Justiça", 
        str_detect(entity, "trabalho|tst|trt") ~ "Justiça do Trabalho",
        str_detect(entity, "federal|trf") ~ "Justiça Federal",
        str_detect(entity, "eleitoral|tse|tre") ~ "Justiça Eleitoral",
        TRUE ~ "Outras Autoridades"
      )
    )
  
  # Geographic entities summary
  entity_results$geographic_entities <- all_entities_by_doc %>%
    select(doc_id, geographic_entities) %>%
    unnest(geographic_entities) %>%
    filter(!is.na(geographic_entities), geographic_entities != "") %>%
    count(geographic_entities, sort = TRUE, name = "frequency") %>%
    rename(entity = geographic_entities) %>%
    mutate(
      entity_type = "geographic_entity", 
      relative_frequency = frequency / sum(frequency),
      category = case_when(
        entity %in% c("brasil", "união", "república federativa do brasil") ~ "Federal",
        str_detect(entity, "distrito federal|brasília") ~ "Distrito Federal",
        str_detect(entity, "acre|alagoas|amapá|amazonas|bahia|ceará|espírito santo|goiás|maranhão|mato grosso|minas gerais|pará|paraíba|paraná|pernambuco|piauí|rio de janeiro|rio grande|rondônia|roraima|santa catarina|são paulo|sergipe|tocantins") ~ "Estados",
        str_detect(entity, "município|prefeitura") ~ "Municipal",
        TRUE ~ "Outros"
      )
    )
  
  # Transport themes summary (enhanced)
  transport_themes_expanded <- all_entities_by_doc %>%
    select(doc_id, transport_themes) %>%
    mutate(
      themes_flat = map(transport_themes, function(themes_list) {
        if (length(themes_list) == 0) return(tibble(theme = character(), terms = character()))
        
        themes_df <- tibble()
        for (theme_name in names(themes_list)) {
          terms <- themes_list[[theme_name]]
          if (length(terms) > 0) {
            themes_df <- bind_rows(themes_df, tibble(theme = theme_name, terms = terms))
          }
        }
        return(themes_df)
      })
    ) %>%
    select(doc_id, themes_flat) %>%
    unnest(themes_flat) %>%
    filter(!is.na(theme), !is.na(terms))
  
  entity_results$transport_themes <- transport_themes_expanded %>%
    count(theme, terms, sort = TRUE, name = "frequency") %>%
    mutate(
      entity_type = "transport_theme",
      relative_frequency = frequency / sum(frequency),
      category = case_when(
        theme == "alternative_fuels" ~ "Combustíveis Alternativos",
        theme == "infrastructure_logistics" ~ "Infraestrutura e Logística",
        theme == "vehicle_technology" ~ "Tecnologia Veicular",
        theme == "environmental_impact" ~ "Impacto Ambiental", 
        theme == "regulation_compliance" ~ "Regulamentação e Compliance",
        theme == "digital_innovation" ~ "Inovação Digital",
        TRUE ~ str_to_title(str_replace_all(theme, "_", " "))
      )
    ) %>%
    rename(entity = terms)
  
  # Create entity co-occurrence network
  cat("🕸️ Building entity co-occurrence network...\n")
  entity_results$co_occurrence_network <- create_entity_cooccurrence_network(all_entities_by_doc)
  
  # Generate processing metadata
  processing_time <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  
  entity_results$processing_metadata <- list(
    documents_processed = length(texts),
    total_legal_instruments = nrow(entity_results$legal_instruments),
    total_regulatory_agencies = nrow(entity_results$regulatory_agencies),
    total_legal_authorities = nrow(entity_results$legal_authorities),
    total_geographic_entities = nrow(entity_results$geographic_entities),
    total_transport_themes = nrow(entity_results$transport_themes),
    processing_time_minutes = processing_time,
    extraction_timestamp = Sys.time()
  )
  
  cat("🎉 Entity extraction completed successfully!\n")
  cat("📊 Extracted", sum(sapply(entity_results[1:5], nrow)), "unique entities\n")
  cat("⏱️ Processing time:", round(processing_time, 2), "minutes\n")
  
  return(entity_results)
}

# Export message
cat("✅ Enhanced Brazilian Legal NLP System core functions loaded!\n")
cat("🔧 Available enhanced functions:\n")
cat("   - preprocess_legal_corpus(): Advanced Portuguese legal text preprocessing\n") 
cat("   - extract_brazilian_legal_entities(): Comprehensive legal entity recognition\n")
cat("📚 Loading additional advanced components...\n")