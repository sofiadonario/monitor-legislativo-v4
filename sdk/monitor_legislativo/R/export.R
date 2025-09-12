#' @title Funções de Exportação do Monitor Legislativo
#' @description Funções para exportar dados legislativos em diversos formatos para análise e pesquisa
#' @author Monitor Legislativo Research Team
#' @importFrom dplyr tibble bind_rows filter arrange select mutate
#' @importFrom purrr map_dfr map_chr safely
#' @importFrom readr write_csv write_tsv
#' @importFrom jsonlite toJSON write_json
#' @importFrom cli cli_alert_info cli_alert_success cli_alert_error cli_progress_bar
#' @importFrom glue glue

#' Exportar dados para arquivo
#'
#' @description
#' Exporta dados de documentos legislativos para diversos formatos de arquivo,
#' incluindo CSV, JSON, Excel, e formatos acadêmicos especializados.
#'
#' @param data tibble. Dados para exportar (resultado de ml_search ou ml_get_documents).
#' @param file_path String. Caminho do arquivo de saída.
#' @param format String. Formato de exportação: "csv", "json", "excel", "tsv", "rdata", "parquet".
#' @param include_metadata Logical. Incluir metadados no arquivo.
#' @param compression String. Tipo de compressão: "none", "gzip", "bzip2", "xz".
#' @param encoding String. Codificação do arquivo: "UTF-8", "latin1".
#' @param chunk_size Integer. Tamanho do chunk para arquivos grandes.
#' 
#' @return Logical. TRUE se exportação bem-sucedida.
#' 
#' @examples
#' \dontrun{
#' # Buscar dados e exportar para CSV
#' docs <- ml_search("meio ambiente", limit = 1000)
#' ml_export_data(docs, "meio_ambiente.csv", format = "csv")
#' 
#' # Exportar para JSON com metadados
#' ml_export_data(
#'   data = docs,
#'   file_path = "meio_ambiente.json",
#'   format = "json",
#'   include_metadata = TRUE
#' )
#' 
#' # Exportar para Excel comprimido
#' ml_export_data(
#'   data = docs,
#'   file_path = "meio_ambiente.xlsx",
#'   format = "excel",
#'   compression = "gzip"
#' )
#' 
#' # Exportar arquivo grande em chunks
#' big_data <- ml_search("lei", limit = 5000)
#' ml_export_data(
#'   data = big_data,
#'   file_path = "leis_grandes.csv",
#'   chunk_size = 1000
#' )
#' }
#' 
#' @export
ml_export_data <- function(data,
                          file_path,
                          format = "csv",
                          include_metadata = TRUE,
                          compression = "none",
                          encoding = "UTF-8",
                          chunk_size = NULL) {
  
  # Validar parâmetros
  if (!is.data.frame(data) || nrow(data) == 0) {
    cli_alert_error("Dados devem ser um data.frame não vazio")
    return(FALSE)
  }
  
  if (!format %in% c("csv", "json", "excel", "tsv", "rdata", "parquet")) {
    stop("format deve ser um de: 'csv', 'json', 'excel', 'tsv', 'rdata', 'parquet'")
  }
  
  if (!compression %in% c("none", "gzip", "bzip2", "xz")) {
    stop("compression deve ser um de: 'none', 'gzip', 'bzip2', 'xz'")
  }
  
  cli_alert_info(glue("Exportando {nrow(data)} registros para {format}..."))
  
  # Preparar metadados se solicitado
  metadata <- NULL
  if (include_metadata) {
    metadata <- list(
      export_date = as.character(Sys.time()),
      total_records = nrow(data),
      columns = names(data),
      format = format,
      encoding = encoding,
      source = "Monitor Legislativo API",
      package_version = "1.0.0"
    )
    
    # Adicionar metadados específicos se disponíveis nos atributos
    if (!is.null(attr(data, "search_meta"))) {
      metadata$search_info <- attr(data, "search_meta")
    }
    
    if (!is.null(attr(data, "search_query"))) {
      metadata$search_query <- attr(data, "search_query")
    }
  }
  
  tryCatch({
    # Exportar baseado no formato
    if (format == "csv") {
      .export_csv(data, file_path, metadata, compression, encoding, chunk_size)
      
    } else if (format == "json") {
      .export_json(data, file_path, metadata, compression, encoding)
      
    } else if (format == "excel") {
      .export_excel(data, file_path, metadata, compression)
      
    } else if (format == "tsv") {
      .export_tsv(data, file_path, metadata, compression, encoding, chunk_size)
      
    } else if (format == "rdata") {
      .export_rdata(data, file_path, metadata, compression)
      
    } else if (format == "parquet") {
      .export_parquet(data, file_path, metadata, compression)
    }
    
    cli_alert_success(glue("Dados exportados para: {file_path}"))
    return(TRUE)
    
  }, error = function(e) {
    cli_alert_error(glue("Erro na exportação: {e$message}"))
    return(FALSE)
  })
}

# Funções internas para exportação específica por formato

.export_csv <- function(data, file_path, metadata, compression, encoding, chunk_size) {
  
  # Determinar se usar chunks
  if (!is.null(chunk_size) && nrow(data) > chunk_size) {
    # Exportação em chunks
    cli_alert_info(glue("Exportando em chunks de {chunk_size} registros"))
    
    n_chunks <- ceiling(nrow(data) / chunk_size)
    base_name <- tools::file_path_sans_ext(file_path)
    ext <- tools::file_ext(file_path)
    
    for (i in 1:n_chunks) {
      start_row <- (i - 1) * chunk_size + 1
      end_row <- min(i * chunk_size, nrow(data))
      chunk_data <- data[start_row:end_row, ]
      
      chunk_file <- glue("{base_name}_chunk_{i}.{ext}")
      
      if (compression == "gzip") {
        chunk_file <- paste0(chunk_file, ".gz")
        conn <- gzfile(chunk_file, "wt", encoding = encoding)
      } else if (compression == "bzip2") {
        chunk_file <- paste0(chunk_file, ".bz2")
        conn <- bzfile(chunk_file, "wt", encoding = encoding)
      } else if (compression == "xz") {
        chunk_file <- paste0(chunk_file, ".xz")
        conn <- xzfile(chunk_file, "wt", encoding = encoding)
      } else {
        conn <- file(chunk_file, "wt", encoding = encoding)
      }
      
      write_csv(chunk_data, conn)
      close(conn)
    }
    
    # Criar arquivo de manifesto
    manifest <- list(
      chunks = n_chunks,
      chunk_size = chunk_size,
      total_records = nrow(data),
      files = paste0(base_name, "_chunk_", 1:n_chunks, ".", ext)
    )
    
    if (!is.null(metadata)) {
      manifest$metadata <- metadata
    }
    
    manifest_file <- paste0(base_name, "_manifest.json")
    write_json(manifest, manifest_file, auto_unbox = TRUE, pretty = TRUE)
    
  } else {
    # Exportação simples
    if (compression == "gzip") {
      file_path <- paste0(file_path, ".gz")
      conn <- gzfile(file_path, "wt", encoding = encoding)
    } else if (compression == "bzip2") {
      file_path <- paste0(file_path, ".bz2")
      conn <- bzfile(file_path, "wt", encoding = encoding)
    } else if (compression == "xz") {
      file_path <- paste0(file_path, ".xz")
      conn <- xzfile(file_path, "wt", encoding = encoding)
    } else {
      conn <- file(file_path, "wt", encoding = encoding)
    }
    
    write_csv(data, conn)
    close(conn)
    
    # Escrever metadados separadamente se solicitado
    if (!is.null(metadata)) {
      metadata_file <- paste0(tools::file_path_sans_ext(file_path), "_metadata.json")
      write_json(metadata, metadata_file, auto_unbox = TRUE, pretty = TRUE)
    }
  }
}

.export_json <- function(data, file_path, metadata, compression, encoding) {
  
  # Preparar dados para JSON
  json_data <- list(
    data = data
  )
  
  if (!is.null(metadata)) {
    json_data$metadata <- metadata
  }
  
  # Escrever JSON
  if (compression == "gzip") {
    file_path <- paste0(file_path, ".gz")
    conn <- gzfile(file_path, "wt", encoding = encoding)
  } else if (compression == "bzip2") {
    file_path <- paste0(file_path, ".bz2")
    conn <- bzfile(file_path, "wt", encoding = encoding)
  } else if (compression == "xz") {
    file_path <- paste0(file_path, ".xz")
    conn <- xzfile(file_path, "wt", encoding = encoding)
  } else {
    conn <- file(file_path, "wt", encoding = encoding)
  }
  
  write_json(json_data, conn, auto_unbox = TRUE, pretty = TRUE)
  close(conn)
}

.export_excel <- function(data, file_path, metadata, compression) {
  
  if (!requireNamespace("writexl", quietly = TRUE)) {
    stop("Pacote writexl é necessário para exportar Excel")
  }
  
  # Preparar lista de planilhas
  sheets <- list(
    "Dados" = data
  )
  
  if (!is.null(metadata)) {
    # Converter metadados para tibble
    metadata_df <- tibble(
      Campo = names(metadata),
      Valor = map_chr(metadata, function(x) {
        if (is.list(x)) {
          jsonlite::toJSON(x, auto_unbox = TRUE)
        } else {
          as.character(x)
        }
      })
    )
    
    sheets$"Metadados" <- metadata_df
  }
  
  # Escrever Excel
  writexl::write_xlsx(sheets, file_path)
  
  # Comprimir se solicitado
  if (compression != "none") {
    compressed_file <- paste0(file_path, ".gz")
    R.utils::gzip(file_path, destname = compressed_file, remove = TRUE)
  }
}

.export_tsv <- function(data, file_path, metadata, compression, encoding, chunk_size) {
  
  # Similar ao CSV, mas com tabs
  if (!is.null(chunk_size) && nrow(data) > chunk_size) {
    cli_alert_info(glue("Exportando TSV em chunks de {chunk_size} registros"))
    
    n_chunks <- ceiling(nrow(data) / chunk_size)
    base_name <- tools::file_path_sans_ext(file_path)
    ext <- tools::file_ext(file_path)
    
    for (i in 1:n_chunks) {
      start_row <- (i - 1) * chunk_size + 1
      end_row <- min(i * chunk_size, nrow(data))
      chunk_data <- data[start_row:end_row, ]
      
      chunk_file <- glue("{base_name}_chunk_{i}.{ext}")
      
      if (compression != "none") {
        chunk_file <- paste0(chunk_file, ".gz")
        conn <- gzfile(chunk_file, "wt", encoding = encoding)
      } else {
        conn <- file(chunk_file, "wt", encoding = encoding)
      }
      
      write_tsv(chunk_data, conn)
      close(conn)
    }
  } else {
    if (compression != "none") {
      file_path <- paste0(file_path, ".gz")
      conn <- gzfile(file_path, "wt", encoding = encoding)
    } else {
      conn <- file(file_path, "wt", encoding = encoding)
    }
    
    write_tsv(data, conn)
    close(conn)
  }
}

.export_rdata <- function(data, file_path, metadata, compression) {
  
  # Criar objeto com nome apropriado
  monitor_legislativo_data <- data
  
  if (!is.null(metadata)) {
    attr(monitor_legislativo_data, "metadata") <- metadata
  }
  
  # Salvar RData
  save(monitor_legislativo_data, file = file_path, compress = compression != "none")
}

.export_parquet <- function(data, file_path, metadata, compression) {
  
  if (!requireNamespace("arrow", quietly = TRUE)) {
    stop("Pacote arrow é necessário para exportar Parquet")
  }
  
  # Adicionar metadados como atributos se disponível
  if (!is.null(metadata)) {
    for (name in names(metadata)) {
      attr(data, name) <- metadata[[name]]
    }
  }
  
  # Escrever Parquet
  arrow::write_parquet(data, file_path, compression = if (compression == "none") "uncompressed" else compression)
}

#' Download em lote de documentos
#'
#' @description
#' Realiza download em lote de documentos legislativos com suas citações,
#' metadados e conteúdo completo, organizados em estrutura de diretórios.
#'
#' @param document_ids Vector. IDs dos documentos para download.
#' @param output_dir String. Diretório de saída para organizar arquivos.
#' @param include_content Logical. Incluir conteúdo completo dos documentos.
#' @param include_citations Logical. Gerar citações ABNT para cada documento.
#' @param include_metadata Logical. Incluir arquivos de metadados detalhados.
#' @param organize_by String. Critério de organização: "category", "state", "date", "none".
#' @param batch_size Integer. Tamanho do lote para processamento.
#' @param parallel Logical. Usar processamento paralelo.
#' 
#' @return List com estatísticas do download e estrutura criada.
#' 
#' @examples
#' \dontrun{
#' # Download básico
#' doc_ids <- c("doc_1", "doc_2", "doc_3")
#' ml_bulk_download(
#'   document_ids = doc_ids,
#'   output_dir = "downloads/legislacao",
#'   include_content = TRUE
#' )
#' 
#' # Download organizado por categoria
#' search_results <- ml_search("sustentabilidade", limit = 100)
#' ml_bulk_download(
#'   document_ids = search_results$id,
#'   output_dir = "pesquisa_sustentabilidade",
#'   organize_by = "category",
#'   include_citations = TRUE
#' )
#' 
#' # Download paralelo para grande volume
#' ml_bulk_download(
#'   document_ids = large_dataset$id,
#'   output_dir = "dataset_completo",
#'   batch_size = 100,
#'   parallel = TRUE
#' )
#' }
#' 
#' @export
ml_bulk_download <- function(document_ids,
                            output_dir,
                            include_content = TRUE,
                            include_citations = TRUE,
                            include_metadata = TRUE,
                            organize_by = "category",
                            batch_size = 50,
                            parallel = FALSE) {
  
  # Validar parâmetros
  if (length(document_ids) == 0) {
    cli_alert_error("Lista de IDs não pode estar vazia")
    return(NULL)
  }
  
  if (!organize_by %in% c("category", "state", "date", "none")) {
    stop("organize_by deve ser um de: 'category', 'state', 'date', 'none'")
  }
  
  # Criar diretório de saída
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
  }
  
  batch_size <- max(1, min(as.integer(batch_size), 200))
  total_docs <- length(document_ids)
  
  cli_alert_info(glue("Iniciando download de {total_docs} documentos..."))
  
  # Criar estrutura de diretórios
  dirs_created <- .create_download_structure(output_dir, organize_by)
  
  # Dividir em lotes
  batches <- split(document_ids, ceiling(seq_along(document_ids) / batch_size))
  
  # Configurar progresso
  pb <- cli_progress_bar(
    total = total_docs,
    format = "Baixando documentos {cli::pb_current}/{cli::pb_total} [{cli::pb_percent}] ETA: {cli::pb_eta}"
  )
  
  # Estatísticas
  stats <- list(
    total_requested = total_docs,
    successfully_downloaded = 0,
    failed_downloads = 0,
    files_created = 0,
    directories_created = length(dirs_created),
    start_time = Sys.time()
  )
  
  # Processar lotes
  for (i in seq_along(batches)) {
    batch_ids <- batches[[i]]
    
    tryCatch({
      # Obter documentos do lote
      batch_docs <- ml_get_documents(
        document_ids = batch_ids,
        include_content = include_content,
        on_error = "skip"
      )
      
      if (nrow(batch_docs) > 0) {
        # Processar cada documento
        for (j in 1:nrow(batch_docs)) {
          doc <- batch_docs[j, ]
          
          # Determinar diretório de destino
          dest_dir <- .determine_destination_dir(doc, output_dir, organize_by)
          
          # Criar arquivos do documento
          files_created <- .create_document_files(
            doc, dest_dir, include_content, include_citations, include_metadata
          )
          
          stats$files_created <- stats$files_created + length(files_created)
          stats$successfully_downloaded <- stats$successfully_downloaded + 1
          
          cli_progress_update()
        }
      }
      
    }, error = function(e) {
      cli_alert_error(glue("Erro no lote {i}: {e$message}"))
      stats$failed_downloads <- stats$failed_downloads + length(batch_ids)
      
      # Atualizar progresso mesmo com erro
      for (k in seq_along(batch_ids)) {
        cli_progress_update()
      }
    })
  }
  
  cli_progress_done()
  
  # Finalizar estatísticas
  stats$end_time <- Sys.time()
  stats$duration <- difftime(stats$end_time, stats$start_time, units = "mins")
  
  # Criar arquivo de índice
  index_file <- file.path(output_dir, "download_index.json")
  index_data <- list(
    download_info = stats,
    structure = dirs_created,
    organization = organize_by,
    generated_at = as.character(Sys.time())
  )
  
  write_json(index_data, index_file, auto_unbox = TRUE, pretty = TRUE)
  stats$files_created <- stats$files_created + 1
  
  cli_alert_success(glue("Download concluído: {stats$successfully_downloaded}/{total_docs} documentos baixados"))
  
  return(stats)
}

# Funções auxiliares para download em lote

.create_download_structure <- function(output_dir, organize_by) {
  
  dirs_created <- c(output_dir)
  
  if (organize_by == "category") {
    # Criar diretórios por categoria comum
    categories <- c("Lei", "Decreto", "Portaria", "Resolução", "Instrução Normativa")
    for (cat in categories) {
      cat_dir <- file.path(output_dir, .sanitize_filename(cat))
      if (!dir.exists(cat_dir)) {
        dir.create(cat_dir, recursive = TRUE)
        dirs_created <- c(dirs_created, cat_dir)
      }
    }
  } else if (organize_by == "state") {
    # Criar diretórios por estado
    states <- c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE")
    for (state in states) {
      state_dir <- file.path(output_dir, state)
      if (!dir.exists(state_dir)) {
        dir.create(state_dir, recursive = TRUE)
        dirs_created <- c(dirs_created, state_dir)
      }
    }
  } else if (organize_by == "date") {
    # Criar diretórios por ano
    current_year <- as.integer(format(Sys.Date(), "%Y"))
    for (year in (current_year - 10):current_year) {
      year_dir <- file.path(output_dir, as.character(year))
      if (!dir.exists(year_dir)) {
        dir.create(year_dir, recursive = TRUE)
        dirs_created <- c(dirs_created, year_dir)
      }
    }
  }
  
  return(dirs_created)
}

.determine_destination_dir <- function(doc, output_dir, organize_by) {
  
  if (organize_by == "category") {
    category <- .sanitize_filename(doc$category %||% "Outros")
    return(file.path(output_dir, category))
  } else if (organize_by == "state") {
    state <- doc$state %||% "Nacional"
    return(file.path(output_dir, state))
  } else if (organize_by == "date") {
    year <- str_extract(doc$date %||% "", "\\d{4}") %||% "Sem_Data"
    return(file.path(output_dir, year))
  } else {
    return(output_dir)
  }
}

.create_document_files <- function(doc, dest_dir, include_content, include_citations, include_metadata) {
  
  files_created <- c()
  
  # Garantir que diretório existe
  if (!dir.exists(dest_dir)) {
    dir.create(dest_dir, recursive = TRUE)
  }
  
  # Nome base do arquivo
  doc_id <- doc$id %||% "unknown"
  safe_title <- .sanitize_filename(substr(doc$title %||% "documento", 1, 50))
  base_name <- glue("{doc_id}_{safe_title}")
  
  # Arquivo principal de metadados (sempre criado)
  main_file <- file.path(dest_dir, paste0(base_name, "_info.json"))
  doc_info <- list(
    id = doc$id,
    title = doc$title,
    category = doc$category,
    state = doc$state,
    municipality = doc$municipality,
    date = doc$date,
    author = doc$author,
    summary = doc$summary,
    url = doc$url,
    downloaded_at = as.character(Sys.time())
  )
  
  write_json(doc_info, main_file, auto_unbox = TRUE, pretty = TRUE)
  files_created <- c(files_created, main_file)
  
  # Conteúdo completo se solicitado
  if (include_content && !is.na(doc$content) && nchar(doc$content) > 0) {
    content_file <- file.path(dest_dir, paste0(base_name, "_content.txt"))
    writeLines(doc$content, content_file, useBytes = TRUE)
    files_created <- c(files_created, content_file)
  }
  
  # Citações se solicitadas
  if (include_citations) {
    tryCatch({
      citation <- ml_generate_citations(doc, citation_style = "abnt")
      if (length(citation) > 0 && nchar(citation[1]) > 0) {
        citation_file <- file.path(dest_dir, paste0(base_name, "_citation.txt"))
        writeLines(citation[1], citation_file, useBytes = TRUE)
        files_created <- c(files_created, citation_file)
      }
    }, error = function(e) {
      # Ignorar erros de citação
    })
  }
  
  # Metadados estendidos se solicitados
  if (include_metadata) {
    # Tentar obter metadados adicionais
    tryCatch({
      extended_meta <- ml_get_document_metadata(doc$id, include_stats = TRUE)
      if (nrow(extended_meta) > 0) {
        metadata_file <- file.path(dest_dir, paste0(base_name, "_metadata.json"))
        write_json(extended_meta, metadata_file, auto_unbox = TRUE, pretty = TRUE)
        files_created <- c(files_created, metadata_file)
      }
    }, error = function(e) {
      # Ignorar erros de metadados
    })
  }
  
  return(files_created)
}

.sanitize_filename <- function(name) {
  # Remover caracteres problemáticos para nomes de arquivo
  name <- str_replace_all(name, "[\\/:*?\"<>|]", "_")
  name <- str_replace_all(name, "\\s+", "_")
  name <- str_trim(name)
  return(name)
}

#' Criar dataset personalizado
#'
#' @description
#' Cria um dataset personalizado combinando busca, filtros e processamento
#' específico para necessidades de pesquisa acadêmica.
#'
#' @param search_params List. Parâmetros de busca para coleta de dados.
#' @param filters List. Filtros adicionais a aplicar.
#' @param processing List. Opções de processamento e enriquecimento.
#' @param output_config List. Configurações de saída e formatação.
#' @param dataset_name String. Nome do dataset para identificação.
#' @param description String. Descrição do dataset e seu propósito.
#' 
#' @return List com informações do dataset criado e caminhos dos arquivos.
#' 
#' @examples
#' \dontrun{
#' # Dataset sobre educação
#' education_dataset <- ml_create_dataset(
#'   search_params = list(
#'     query = "educação",
#'     filters = list(category = c("Lei", "Decreto")),
#'     limit = 2000
#'   ),
#'   processing = list(
#'     include_citations = TRUE,
#'     include_geographic = TRUE,
#'     include_temporal_analysis = TRUE
#'   ),
#'   output_config = list(
#'     formats = c("csv", "json", "excel"),
#'     compression = "gzip",
#'     organize_by = "state"
#'   ),
#'   dataset_name = "Legislacao_Educacao_Brasil",
#'   description = "Dataset completo sobre legislação educacional brasileira"
#' )
#' 
#' # Dataset temporal específico
#' covid_dataset <- ml_create_dataset(
#'   search_params = list(
#'     query = "covid OR coronavirus OR pandemia",
#'     filters = list(
#'       date_start = "2020-01-01",
#'       date_end = "2023-12-31"
#'     )
#'   ),
#'   processing = list(
#'     include_trends = TRUE,
#'     include_geographic = TRUE,
#'     temporal_granularity = "month"
#'   ),
#'   dataset_name = "Legislacao_COVID19"
#' )
#' }
#' 
#' @export
ml_create_dataset <- function(search_params,
                             filters = list(),
                             processing = list(),
                             output_config = list(),
                             dataset_name,
                             description = "") {
  
  # Validar parâmetros obrigatórios
  if (missing(search_params) || missing(dataset_name)) {
    stop("search_params e dataset_name são obrigatórios")
  }
  
  # Configurações padrão
  default_output <- list(
    formats = "csv",
    compression = "none",
    organize_by = "none",
    output_dir = paste0("dataset_", dataset_name)
  )
  
  output_config <- modifyList(default_output, output_config)
  
  cli_alert_info(glue("Criando dataset: {dataset_name}"))
  
  # Criar diretório do dataset
  if (!dir.exists(output_config$output_dir)) {
    dir.create(output_config$output_dir, recursive = TRUE)
  }
  
  dataset_info <- list(
    name = dataset_name,
    description = description,
    created_at = Sys.time(),
    search_params = search_params,
    filters = filters,
    processing = processing,
    output_config = output_config,
    files = list(),
    statistics = list()
  )
  
  tryCatch({
    # 1. Coletar dados principais
    cli_alert_info("Coletando dados principais...")
    
    main_search <- do.call(ml_search, c(search_params, list(as_tibble = TRUE)))
    
    if (nrow(main_search) == 0) {
      stop("Nenhum documento encontrado com os parâmetros de busca")
    }
    
    # Aplicar filtros adicionais
    if (length(filters) > 0) {
      main_data <- do.call(ml_filter_documents, c(list(documents = main_search), filters))
    } else {
      main_data <- main_search
    }
    
    dataset_info$statistics$total_documents <- nrow(main_data)
    
    # 2. Processamento adicional baseado nas opções
    processed_data <- list(main = main_data)
    
    # Análise geográfica
    if (processing$include_geographic %||% FALSE) {
      cli_alert_info("Executando análise geográfica...")
      geo_analysis <- ml_geographic_analysis(
        geographic_level = processing$geographic_level %||% "state",
        aggregation = processing$geographic_aggregation %||% "count"
      )
      processed_data$geographic <- geo_analysis
    }
    
    # Análise temporal
    if (processing$include_temporal_analysis %||% FALSE) {
      cli_alert_info("Executando análise temporal...")
      temporal_analysis <- ml_analyze_trends(
        time_granularity = processing$temporal_granularity %||% "month",
        trend_analysis = processing$temporal_metrics %||% c("volume", "diversity")
      )
      processed_data$temporal <- temporal_analysis
    }
    
    # Citações
    if (processing$include_citations %||% FALSE) {
      cli_alert_info("Gerando citações...")
      citations <- ml_generate_citations(main_data)
      processed_data$citations <- citations
    }
    
    # Métricas
    if (processing$include_metrics %||% FALSE) {
      cli_alert_info("Calculando métricas...")
      metrics <- ml_get_metrics(breakdown_by = "category")
      processed_data$metrics <- metrics
    }
    
    # 3. Exportar dados nos formatos solicitados
    cli_alert_info("Exportando dados...")
    
    formats <- if (is.character(output_config$formats)) {
      output_config$formats
    } else {
      c("csv")
    }
    
    for (format in formats) {
      # Dados principais
      main_file <- file.path(
        output_config$output_dir,
        paste0(dataset_name, "_main.", format)
      )
      
      ml_export_data(
        data = main_data,
        file_path = main_file,
        format = format,
        compression = output_config$compression,
        include_metadata = TRUE
      )
      
      dataset_info$files[[paste0("main_", format)]] <- main_file
      
      # Dados processados adicionais
      for (data_type in names(processed_data)) {
        if (data_type != "main" && is.data.frame(processed_data[[data_type]])) {
          additional_file <- file.path(
            output_config$output_dir,
            paste0(dataset_name, "_", data_type, ".", format)
          )
          
          ml_export_data(
            data = processed_data[[data_type]],
            file_path = additional_file,
            format = format,
            compression = output_config$compression
          )
          
          dataset_info$files[[paste0(data_type, "_", format)]] <- additional_file
        }
      }
    }
    
    # 4. Criar documentação do dataset
    cli_alert_info("Criando documentação...")
    
    # README
    readme_content <- .create_dataset_readme(dataset_info, main_data, processed_data)
    readme_file <- file.path(output_config$output_dir, "README.md")
    writeLines(readme_content, readme_file, useBytes = TRUE)
    dataset_info$files$readme <- readme_file
    
    # Metadados completos
    metadata_file <- file.path(output_config$output_dir, "dataset_metadata.json")
    write_json(dataset_info, metadata_file, auto_unbox = TRUE, pretty = TRUE)
    dataset_info$files$metadata <- metadata_file
    
    # Estatísticas finais
    dataset_info$statistics$files_created <- length(dataset_info$files)
    dataset_info$statistics$processing_time <- difftime(Sys.time(), dataset_info$created_at, units = "mins")
    
    cli_alert_success(glue("Dataset '{dataset_name}' criado com {dataset_info$statistics$total_documents} documentos"))
    
    return(dataset_info)
    
  }, error = function(e) {
    cli_alert_error(glue("Erro na criação do dataset: {e$message}"))
    return(NULL)
  })
}

# Função auxiliar para criar README do dataset
.create_dataset_readme <- function(dataset_info, main_data, processed_data) {
  
  readme_lines <- c(
    glue("# {dataset_info$name}"),
    "",
    glue("**Descrição:** {dataset_info$description}"),
    "",
    glue("**Criado em:** {dataset_info$created_at}"),
    glue("**Fonte:** Monitor Legislativo API v4"),
    "",
    "## Estatísticas do Dataset",
    "",
    glue("- **Total de documentos:** {dataset_info$statistics$total_documents}"),
    glue("- **Período coberto:** {min(main_data$date, na.rm = TRUE)} a {max(main_data$date, na.rm = TRUE)}"),
    glue("- **Estados cobertos:** {length(unique(main_data$state[!is.na(main_data$state) & main_data$state != '']))}"),
    glue("- **Categorias:** {length(unique(main_data$category[!is.na(main_data$category)]))}"),
    "",
    "## Arquivos Incluídos",
    ""
  )
  
  # Listar arquivos
  for (file_type in names(dataset_info$files)) {
    file_path <- basename(dataset_info$files[[file_type]])
    readme_lines <- c(readme_lines, glue("- `{file_path}`: {file_type}"))
  }
  
  readme_lines <- c(
    readme_lines,
    "",
    "## Parâmetros de Busca",
    "",
    glue("- **Query:** {dataset_info$search_params$query %||% 'N/A'}"),
    glue("- **Limite:** {dataset_info$search_params$limit %||% 'N/A'}"),
    ""
  )
  
  # Adicionar informações de processamento se disponível
  if (length(processed_data) > 1) {
    readme_lines <- c(
      readme_lines,
      "## Processamento Adicional",
      ""
    )
    
    for (proc_type in names(processed_data)) {
      if (proc_type != "main") {
        readme_lines <- c(readme_lines, glue("- **{str_to_title(proc_type)}:** Incluído"))
      }
    }
  }
  
  readme_lines <- c(
    readme_lines,
    "",
    "## Como Citar",
    "",
    "Monitor Legislativo Research Team. (2024). Monitor Legislativo v4 API.",
    "https://monitor-legislativo-unified-production.up.railway.app",
    "",
    "---",
    "*Dataset gerado automaticamente pelo Monitor Legislativo R SDK*"
  )
  
  return(readme_lines)
}