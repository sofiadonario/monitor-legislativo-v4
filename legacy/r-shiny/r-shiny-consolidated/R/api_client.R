# API Client for Monitor Legislativo v4
# Consolidated R architecture with modern HTTP client

library(httr)
library(jsonlite)
library(dplyr)
library(promises)
library(future)

# Load configuration
source("R/utils.R")

#' Search legislative data using backend API
#' @param query Search query string
#' @param date_from Start date for filtering
#' @param date_to End date for filtering
#' @param types Document types to include
#' @param states States to include
#' @param limit Maximum number of results
#' @return Data frame with legislative data
search_legislative_data <- function(query = NULL, date_from = NULL, date_to = NULL,
                                  types = NULL, states = NULL, limit = 1000) {
  
  log_event(paste("Starting legislative search with query:", query %||% "all"))
  
  # Validate inputs
  query <- sanitize_query(query)
  date_from <- validate_date(date_from)
  date_to <- validate_date(date_to)
  limit <- min(max(as.numeric(limit), 1), 5000)  # Ensure reasonable limits
  
  # Get configuration
  config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
  app_config <- config::get(config = config_env)
  
  # Build API URL
  base_url <- app_config$apis$backend$base_url
  endpoint <- app_config$apis$lexml$enhanced_endpoint
  full_url <- paste0(base_url, endpoint)
  
  # Build query parameters
  params <- list()
  
  if (!is.null(query) && query != "") {
    params$query <- query
  } else {
    params$query <- "transporte"  # Default search term
  }
  
  if (!is.null(date_from)) {
    params$date_from <- format(date_from, "%Y-%m-%d")
  }
  
  if (!is.null(date_to)) {
    params$date_to <- format(date_to, "%Y-%m-%d")
  }
  
  if (!is.null(types) && length(types) > 0 && !"all" %in% types) {
    params$types <- paste(types, collapse = ",")
  }
  
  if (!is.null(states) && length(states) > 0) {
    params$states <- paste(states, collapse = ",")
  }
  
  params$limit <- limit
  
  # Make API request
  tryCatch({
    log_event("Making API request to backend")
    
    response <- GET(
      url = full_url,
      query = params,
      add_headers(
        "Accept" = "application/json",
        "User-Agent" = "Monitor-Legislativo-R/1.0",
        "Content-Type" = "application/json"
      ),
      timeout(app_config$apis$backend$timeout)
    )
    
    # Check response status
    if (status_code(response) != 200) {
      error_msg <- paste("API error: HTTP", status_code(response))
      if (status_code(response) == 404) {
        error_msg <- paste(error_msg, "- Endpoint not found")
      } else if (status_code(response) >= 500) {
        error_msg <- paste(error_msg, "- Server error")
      }
      
      log_event(error_msg, "ERROR")
      return(create_fallback_data(query))
    }
    
    # Parse JSON response
    content_data <- content(response, "text", encoding = "UTF-8")
    
    if (content_data == "" || is.null(content_data)) {
      log_event("Empty response from API", "WARN")
      return(create_fallback_data(query))
    }
    
    parsed_data <- fromJSON(content_data, flatten = TRUE)
    
    # Handle different response structures
    if (is.data.frame(parsed_data)) {
      result_data <- parsed_data
    } else if (is.list(parsed_data) && "data" %in% names(parsed_data)) {
      result_data <- parsed_data$data
    } else if (is.list(parsed_data) && "results" %in% names(parsed_data)) {
      result_data <- parsed_data$results
    } else {
      log_event("Unexpected API response structure", "WARN")
      return(create_fallback_data(query))
    }
    
    # Validate and process data
    if (is.data.frame(result_data) && nrow(result_data) > 0) {
      
      # Standardize column names
      result_data <- standardize_columns(result_data)
      
      # Validate data quality
      result_data <- validate_data_quality(result_data)
      
      # Remove duplicates
      result_data <- remove_duplicates(result_data)
      
      # Add metadata
      result_data$data_coleta <- Sys.time()
      result_data$fonte_api <- "Backend Enhanced Search"
      
      log_event(paste("Successfully retrieved", nrow(result_data), "documents"))
      return(result_data)
      
    } else {
      log_event("No valid data in API response", "WARN")
      return(create_fallback_data(query))
    }
    
  }, error = function(e) {
    log_event(paste("API request failed:", e$message), "ERROR")
    return(create_fallback_data(query))
  })
}

#' Create fallback data when API is unavailable
#' @param query Original search query
#' @return Sample data frame
create_fallback_data <- function(query = NULL) {
  log_event("Creating fallback data", "INFO")
  
  # Load local CSV data as fallback
  fallback_file <- "data/lexml_parsed_enhanced.csv"
  
  if (file.exists(fallback_file)) {
    tryCatch({
      fallback_data <- read.csv(fallback_file, stringsAsFactors = FALSE, encoding = "UTF-8")
      
      # Filter by query if provided
      if (!is.null(query) && query != "") {
        search_pattern <- paste(unlist(strsplit(query, "\\s+")), collapse = "|")
        fallback_data <- fallback_data %>%
          filter(
            grepl(search_pattern, titulo, ignore.case = TRUE) |
            grepl(search_pattern, ementa, ignore.case = TRUE)
          )
      }
      
      # Standardize and validate
      fallback_data <- standardize_columns(fallback_data)
      fallback_data <- validate_data_quality(fallback_data)
      
      # Add metadata
      fallback_data$data_coleta <- Sys.time()
      fallback_data$fonte_api <- "Local Fallback Data"
      
      log_event(paste("Loaded", nrow(fallback_data), "documents from fallback"))
      return(fallback_data)
      
    }, error = function(e) {
      log_event(paste("Failed to load fallback data:", e$message), "ERROR")
    })
  }
  
  # If all else fails, create minimal sample data
  log_event("Creating minimal sample data", "WARN")
  
  sample_data <- data.frame(
    titulo = c(
      "Lei de Diretrizes e Bases da Educação Nacional",
      "Código de Trânsito Brasileiro",
      "Lei de Responsabilidade Fiscal",
      "Estatuto da Criança e do Adolescente",
      "Lei Maria da Penha"
    ),
    tipo = c("Lei", "Lei", "Lei Complementar", "Lei", "Lei"),
    numero = c("9394", "9503", "101", "8069", "11340"),
    data = as.Date(c("1996-12-20", "1997-09-23", "2000-05-04", "1990-07-13", "2006-08-07")),
    estado = c("DF", "DF", "DF", "DF", "DF"),
    autor = c("Congresso Nacional", "Congresso Nacional", "Congresso Nacional", "Congresso Nacional", "Congresso Nacional"),
    fonte = "Dados de Exemplo",
    ementa = c(
      "Estabelece as diretrizes e bases da educação nacional",
      "Institui o Código de Trânsito Brasileiro",
      "Estabelece normas de finanças públicas voltadas para a responsabilidade na gestão fiscal",
      "Dispõe sobre o Estatuto da Criança e do Adolescente",
      "Cria mecanismos para coibir a violência doméstica e familiar contra a mulher"
    ),
    quality_score = rep(95, 5),
    data_coleta = Sys.time(),
    fonte_api = "Sample Data",
    stringsAsFactors = FALSE
  )
  
  return(sample_data)
}

#' Check API status for all configured endpoints
#' @return List with status information for each API
check_apis_status <- function() {
  log_event("Checking API status")
  
  # Get configuration
  config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
  app_config <- config::get(config = config_env)
  
  apis_to_check <- list(
    "Backend Principal" = app_config$apis$backend$base_url,
    "Câmara dos Deputados" = app_config$apis$external$camara$base_url,
    "Senado Federal" = app_config$apis$external$senado$base_url
  )
  
  status_results <- list()
  
  for (api_name in names(apis_to_check)) {
    url <- apis_to_check[[api_name]]
    
    status_results[[api_name]] <- tryCatch({
      response <- GET(url, timeout(10))
      
      list(
        status = if (status_code(response) == 200) "Online" else "Error",
        code = status_code(response),
        response_time = response$times[["total"]]
      )
      
    }, error = function(e) {
      list(
        status = "Offline",
        error = e$message,
        response_time = NA
      )
    })
  }
  
  return(status_results)
}

#' Get vocabulary suggestions for search enhancement
#' @param term Term to get suggestions for
#' @return Vector of related terms
get_vocabulary_suggestions <- function(term) {
  if (is.null(term) || term == "") {
    return(NULL)
  }
  
  # Get configuration
  config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
  app_config <- config::get(config = config_env)
  
  # Build API URL
  base_url <- app_config$apis$backend$base_url
  endpoint <- app_config$apis$lexml$vocabulary_endpoint
  full_url <- paste0(base_url, endpoint)
  
  params <- list(term = term)
  
  tryCatch({
    response <- GET(
      url = full_url,
      query = params,
      add_headers(
        "Accept" = "application/json",
        "User-Agent" = "Monitor-Legislativo-R/1.0"
      ),
      timeout(30)
    )
    
    if (status_code(response) == 200) {
      content_data <- content(response, "text", encoding = "UTF-8")
      suggestions <- fromJSON(content_data)
      
      if (is.character(suggestions)) {
        return(suggestions)
      } else if (is.list(suggestions) && "terms" %in% names(suggestions)) {
        return(suggestions$terms)
      }
    }
    
    return(NULL)
    
  }, error = function(e) {
    log_event(paste("Vocabulary API error:", e$message), "WARN")
    return(NULL)
  })
}

#' Export legislative data to various formats
#' @param data Legislative data to export
#' @param format Export format (csv, xlsx, json, pdf, html)
#' @param options Export options list
#' @param limit Maximum records to export
#' @return File path of exported data
export_legislative_data <- function(data, format = "csv", options = NULL, limit = 1000) {
  
  if (is.null(data) || nrow(data) == 0) {
    log_event("No data to export", "WARN")
    return(NULL)
  }
  
  log_event(paste("Exporting", nrow(data), "records to", format))
  
  # Limit data if specified
  if (!is.null(limit) && limit < nrow(data)) {
    data <- data %>% slice_head(n = limit)
  }
  
  # Prepare data based on options
  if (!is.null(options)) {
    if (!"metadata" %in% options) {
      # Remove metadata columns
      metadata_cols <- c("data_coleta", "fonte_api", "quality_score")
      data <- data %>% select(-any_of(metadata_cols))
    }
    
    if ("stats" %in% options) {
      # Add summary statistics
      stats <- create_summary_stats(data)
      attr(data, "summary_stats") <- stats
    }
  }
  
  # Create exports directory
  if (!dir.exists("exports")) {
    dir.create("exports", recursive = TRUE)
  }
  
  # Generate filename
  timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
  
  tryCatch({
    switch(format,
      "csv" = {
        filename <- paste0("exports/legislativo_", timestamp, ".csv")
        write.csv(data, filename, row.names = FALSE, fileEncoding = "UTF-8")
        return(filename)
      },
      
      "xlsx" = {
        if (require_package("openxlsx", quiet = TRUE)) {
          filename <- paste0("exports/legislativo_", timestamp, ".xlsx")
          
          # Create workbook with multiple sheets
          wb <- openxlsx::createWorkbook()
          
          # Data sheet
          openxlsx::addWorksheet(wb, "Dados")
          openxlsx::writeData(wb, "Dados", data, startRow = 1)
          
          # Summary sheet if stats are included
          if (!is.null(attr(data, "summary_stats"))) {
            stats <- attr(data, "summary_stats")
            openxlsx::addWorksheet(wb, "Resumo")
            
            summary_df <- data.frame(
              Estatistica = names(stats),
              Valor = unlist(stats),
              stringsAsFactors = FALSE
            )
            
            openxlsx::writeData(wb, "Resumo", summary_df, startRow = 1)
          }
          
          openxlsx::saveWorkbook(wb, filename, overwrite = TRUE)
          return(filename)
        } else {
          stop("Package openxlsx not available for Excel export")
        }
      },
      
      "json" = {
        filename <- paste0("exports/legislativo_", timestamp, ".json")
        
        export_list <- list(
          metadata = list(
            exported_at = Sys.time(),
            total_records = nrow(data),
            format = "json"
          ),
          data = data
        )
        
        if (!is.null(attr(data, "summary_stats"))) {
          export_list$summary_stats <- attr(data, "summary_stats")
        }
        
        jsonlite::write_json(export_list, filename, pretty = TRUE, auto_unbox = TRUE)
        return(filename)
      },
      
      "html" = {
        if (require_package("htmltools", quiet = TRUE) && require_package("DT", quiet = TRUE)) {
          filename <- paste0("exports/legislativo_", timestamp, ".html")
          
          # Create HTML report
          html_content <- tags$html(
            tags$head(
              tags$title("Monitor Legislativo - Relatório de Dados"),
              tags$meta(charset = "utf-8"),
              tags$style(HTML("
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1, h2 { color: #0d6efd; }
                .summary { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #0d6efd; color: white; }
                tr:nth-child(even) { background-color: #f2f2f2; }
              "))
            ),
            tags$body(
              tags$h1("Monitor Legislativo - Relatório de Dados"),
              tags$p(paste("Relatório gerado em:", format(Sys.time(), "%d/%m/%Y %H:%M:%S"))),
              
              if (!is.null(attr(data, "summary_stats"))) {
                stats <- attr(data, "summary_stats")
                tags$div(
                  class = "summary",
                  tags$h2("Resumo Estatístico"),
                  tags$p(paste("Total de Documentos:", stats$total_documents)),
                  tags$p(paste("Estados Únicos:", stats$unique_states)),
                  tags$p(paste("Tipos de Documento:", stats$unique_types)),
                  tags$p(paste("Período:", stats$date_range))
                )
              },
              
              tags$h2("Dados Detalhados"),
              tags$div(
                DT::datatable(
                  data %>% select(-any_of(c("data_coleta", "fonte_api", "quality_score"))),
                  options = list(pageLength = 25, scrollX = TRUE),
                  class = "display"
                ) %>% as.character()
              )
            )
          )
          
          writeLines(as.character(html_content), filename)
          return(filename)
        } else {
          stop("Required packages not available for HTML export")
        }
      },
      
      {
        stop("Unsupported export format: ", format)
      }
    )
    
  }, error = function(e) {
    log_event(paste("Export failed:", e$message), "ERROR")
    return(NULL)
  })
}