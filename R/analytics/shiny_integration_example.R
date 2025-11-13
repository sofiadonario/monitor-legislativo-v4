#' Readability Metrics - Shiny Integration Example
#'
#' This file demonstrates how to integrate readability metrics into the
#' Monitor Legislativo v4 Shiny application.
#'
#' @author Monitor Legislativo v4
#' @date 2025-11-12

# ==============================================================================
# SETUP - Add to app.R or global.R
# ==============================================================================

# Source the readability metrics module
source("R/analytics/readability_metrics.R")

# ==============================================================================
# UI COMPONENTS
# ==============================================================================

#' Readability Metrics UI Component
#'
#' Add this to your document detail page or create a new tab
readability_ui <- function(id) {
  ns <- NS(id)

  tagList(
    h3("Métricas de Legibilidade"),

    # Summary card
    fluidRow(
      column(4,
        valueBoxOutput(ns("flesch_box"))
      ),
      column(4,
        valueBoxOutput(ns("fog_box"))
      ),
      column(4,
        valueBoxOutput(ns("smog_box"))
      )
    ),

    hr(),

    # Detailed metrics table
    h4("Detalhes das Métricas"),
    tableOutput(ns("metrics_table")),

    hr(),

    # Text statistics
    h4("Estatísticas do Texto"),
    fluidRow(
      column(6,
        infoBoxOutput(ns("word_count_box"))
      ),
      column(6,
        infoBoxOutput(ns("sentence_count_box"))
      )
    ),

    hr(),

    # Interpretation and recommendations
    h4("Interpretação e Recomendações"),
    uiOutput(ns("interpretation"))
  )
}

# ==============================================================================
# SERVER COMPONENTS
# ==============================================================================

#' Readability Metrics Server Component
#'
#' @param id Module ID
#' @param document_text Reactive expression returning document text
readability_server <- function(id, document_text) {
  moduleServer(id, function(input, output, session) {

    # Calculate metrics reactively
    metrics <- reactive({
      req(document_text())

      text <- document_text()

      if (is.na(text) || text == "") {
        return(NULL)
      }

      # Calculate all metrics
      result <- calculate_all_readability_metrics(text)

      # Add text statistics
      words <- str_split(text, "\\s+")[[1]]
      words <- str_replace_all(words, "[[:punct:]]", "")
      words <- words[words != ""]

      result$word_count <- length(words)
      result$sentence_count <- count_sentences(text)

      result
    })

    # Flesch-Kincaid value box
    output$flesch_box <- renderValueBox({
      req(metrics())

      score <- metrics()$flesch_kincaid

      # Determine color based on score
      color <- if (is.na(score)) {
        "gray"
      } else if (score >= 60) {
        "green"
      } else if (score >= 30) {
        "yellow"
      } else {
        "red"
      }

      valueBox(
        value = ifelse(is.na(score), "N/A", sprintf("%.1f", score)),
        subtitle = "Índice Flesch",
        icon = icon("book-open"),
        color = color
      )
    })

    # FOG Index value box
    output$fog_box <- renderValueBox({
      req(metrics())

      score <- metrics()$fog_index

      # Determine color based on grade level
      color <- if (is.na(score)) {
        "gray"
      } else if (score <= 12) {
        "green"
      } else if (score <= 16) {
        "yellow"
      } else {
        "red"
      }

      valueBox(
        value = ifelse(is.na(score), "N/A", sprintf("%.1f", score)),
        subtitle = "Índice FOG",
        icon = icon("graduation-cap"),
        color = color
      )
    })

    # SMOG Index value box
    output$smog_box <- renderValueBox({
      req(metrics())

      score <- metrics()$smog_index

      color <- if (is.na(score)) {
        "gray"
      } else if (score <= 12) {
        "green"
      } else if (score <= 16) {
        "yellow"
      } else {
        "red"
      }

      valueBox(
        value = ifelse(is.na(score), "N/A", sprintf("%.1f", score)),
        subtitle = "Índice SMOG",
        icon = icon("chart-line"),
        color = color
      )
    })

    # Detailed metrics table
    output$metrics_table <- renderTable({
      req(metrics())

      m <- metrics()

      data.frame(
        Métrica = c(
          "Flesch Reading Ease",
          "Gunning FOG Index",
          "SMOG Index"
        ),
        Pontuação = c(
          ifelse(is.na(m$flesch_kincaid), "N/A", sprintf("%.2f", m$flesch_kincaid)),
          ifelse(is.na(m$fog_index), "N/A", sprintf("%.2f", m$fog_index)),
          ifelse(is.na(m$smog_index), "N/A", sprintf("%.2f", m$smog_index))
        ),
        Interpretação = c(
          interpret_flesch(m$flesch_kincaid),
          interpret_grade_level(m$fog_index),
          interpret_grade_level(m$smog_index)
        ),
        Descrição = c(
          "Facilidade de leitura (0-100, maior = mais fácil)",
          "Nível educacional necessário (anos de estudo)",
          "Nível de escolaridade (anos de estudo)"
        ),
        stringsAsFactors = FALSE
      )
    }, striped = TRUE, hover = TRUE, width = "100%")

    # Word count info box
    output$word_count_box <- renderInfoBox({
      req(metrics())

      infoBox(
        title = "Palavras",
        value = format(metrics()$word_count, big.mark = "."),
        icon = icon("file-word"),
        color = "blue"
      )
    })

    # Sentence count info box
    output$sentence_count_box <- renderInfoBox({
      req(metrics())

      infoBox(
        title = "Sentenças",
        value = format(metrics()$sentence_count, big.mark = "."),
        icon = icon("paragraph"),
        color = "purple"
      )
    })

    # Interpretation and recommendations
    output$interpretation <- renderUI({
      req(metrics())

      m <- metrics()

      if (is.na(m$flesch_kincaid)) {
        return(div(
          class = "alert alert-warning",
          icon("exclamation-triangle"),
          "Não foi possível calcular métricas para este documento."
        ))
      }

      # Determine overall readability
      overall <- if (m$flesch_kincaid >= 60) {
        list(
          level = "Boa Legibilidade",
          class = "alert-success",
          icon = "check-circle"
        )
      } else if (m$flesch_kincaid >= 30) {
        list(
          level = "Legibilidade Moderada",
          class = "alert-warning",
          icon = "exclamation-circle"
        )
      } else {
        list(
          level = "Baixa Legibilidade",
          class = "alert-danger",
          icon = "times-circle"
        )
      }

      # Generate recommendations
      recommendations <- c()

      if (m$flesch_kincaid < 50) {
        recommendations <- c(recommendations,
          "Considere simplificar sentenças longas e complexas",
          "Reduza o uso de palavras técnicas ou polissilábicas quando possível",
          "Divida parágrafos extensos em unidades menores"
        )
      }

      if (m$fog_index > 16) {
        recommendations <- c(recommendations,
          "O texto requer nível de pós-graduação para compreensão",
          "Considere adicionar glossário de termos técnicos"
        )
      }

      avg_words_per_sentence <- m$word_count / m$sentence_count
      if (avg_words_per_sentence > 25) {
        recommendations <- c(recommendations,
          sprintf("Sentenças muito longas (média: %.0f palavras/sentença)",
                  avg_words_per_sentence),
          "Recomenda-se manter sentenças com menos de 20 palavras"
        )
      }

      if (length(recommendations) == 0) {
        recommendations <- c("O documento apresenta boa legibilidade geral")
      }

      tagList(
        div(
          class = paste("alert", overall$class),
          icon(overall$icon),
          strong(overall$level),
          p(interpret_flesch(m$flesch_kincaid))
        ),

        h5("Recomendações:"),
        tags$ul(
          lapply(recommendations, function(rec) {
            tags$li(rec)
          })
        )
      )
    })
  })
}

# ==============================================================================
# EXAMPLE INTEGRATION IN MAIN APP
# ==============================================================================

# In your app_phoenix.R or main app file:

# UI section:
if (FALSE) {
  # Add to your document detail tabs
  tabPanel(
    "Legibilidade",
    icon = icon("book-open"),
    readability_ui("doc_readability")
  )
}

# Server section:
if (FALSE) {
  # Get document text reactively
  current_document_text <- reactive({
    req(input$selected_document_id)

    # Fetch from database
    result <- pool::dbGetQuery(pool,
      "SELECT texto_completo FROM documents WHERE id = ?",
      params = list(input$selected_document_id)
    )

    if (nrow(result) > 0) {
      result$texto_completo[1]
    } else {
      NULL
    }
  })

  # Call readability module
  readability_server("doc_readability", current_document_text)
}

# ==============================================================================
# COMPARISON VIEW - Compare Readability Across Documents
# ==============================================================================

#' Readability Comparison UI
readability_comparison_ui <- function(id) {
  ns <- NS(id)

  tagList(
    h3("Comparação de Legibilidade"),

    # Filters
    fluidRow(
      column(4,
        selectInput(ns("group_by"), "Agrupar por:",
                   choices = c("Tipo de Documento" = "tipo",
                              "Jurisdição" = "jurisdicao",
                              "Ano" = "ano",
                              "Poder" = "poder"))
      ),
      column(4,
        selectInput(ns("metric"), "Métrica:",
                   choices = c("Flesch-Kincaid" = "flesch_kincaid",
                              "FOG Index" = "fog_index",
                              "SMOG Index" = "smog_index"))
      ),
      column(4,
        actionButton(ns("refresh"), "Atualizar", icon = icon("refresh"))
      )
    ),

    hr(),

    # Visualization
    plotOutput(ns("comparison_plot"), height = "500px"),

    hr(),

    # Summary table
    h4("Estatísticas por Grupo"),
    DT::dataTableOutput(ns("summary_table"))
  )
}

#' Readability Comparison Server
readability_comparison_server <- function(id, pool) {
  moduleServer(id, function(input, output, session) {

    # Load data
    comparison_data <- eventReactive(input$refresh, {
      req(pool)

      query <- sprintf("
        SELECT
          d.%s as group_var,
          AVG(rm.flesch_kincaid) as avg_flesch,
          AVG(rm.fog_index) as avg_fog,
          AVG(rm.smog_index) as avg_smog,
          COUNT(*) as n_docs,
          STDDEV(rm.flesch_kincaid) as sd_flesch,
          STDDEV(rm.fog_index) as sd_fog,
          STDDEV(rm.smog_index) as sd_smog
        FROM documents d
        JOIN readability_metrics rm ON d.id = rm.id
        WHERE rm.flesch_kincaid IS NOT NULL
        GROUP BY d.%s
        ORDER BY avg_flesch DESC
      ", input$group_by, input$group_by)

      pool::dbGetQuery(pool, query)
    }, ignoreNULL = FALSE)

    # Plot comparison
    output$comparison_plot <- renderPlot({
      req(comparison_data())

      data <- comparison_data()
      metric_col <- paste0("avg_", gsub("_.*", "", input$metric))

      # Create bar plot
      ggplot(data, aes(x = reorder(group_var, .data[[metric_col]]),
                      y = .data[[metric_col]])) +
        geom_bar(stat = "identity", fill = "#3498db") +
        geom_text(aes(label = sprintf("%.1f", .data[[metric_col]])),
                 hjust = -0.2, size = 4) +
        coord_flip() +
        labs(
          title = sprintf("Média de %s por %s",
                         names(which(c("flesch_kincaid" = "Flesch-Kincaid",
                                      "fog_index" = "FOG Index",
                                      "smog_index" = "SMOG Index") == input$metric)),
                         input$group_by),
          x = "",
          y = "Pontuação Média"
        ) +
        theme_minimal(base_size = 14)
    })

    # Summary table
    output$summary_table <- DT::renderDataTable({
      req(comparison_data())

      data <- comparison_data()

      # Format for display
      data %>%
        transmute(
          Grupo = group_var,
          `N Docs` = format(n_docs, big.mark = "."),
          `Flesch (média)` = sprintf("%.2f ± %.2f", avg_flesch, sd_flesch),
          `FOG (média)` = sprintf("%.2f ± %.2f", avg_fog, sd_fog),
          `SMOG (média)` = sprintf("%.2f ± %.2f", avg_smog, sd_smog)
        ) %>%
        DT::datatable(
          options = list(pageLength = 15, dom = 'tip'),
          rownames = FALSE
        )
    })
  })
}

# ==============================================================================
# CACHED METRICS RETRIEVAL
# ==============================================================================

#' Get Readability Metrics from Cache
#'
#' Retrieves pre-calculated readability metrics from database cache.
#' If not cached, calculates and caches them.
#'
#' @param pool Database connection pool
#' @param document_id Document ID
#' @return List with readability metrics or NULL
get_cached_readability <- function(pool, document_id) {
  # Try to get from cache
  cached <- pool::dbGetQuery(pool,
    "SELECT * FROM readability_metrics WHERE id = ?",
    params = list(document_id)
  )

  if (nrow(cached) > 0) {
    # Return cached metrics
    return(list(
      flesch_kincaid = cached$flesch_kincaid[1],
      fog_index = cached$fog_index[1],
      smog_index = cached$smog_index[1],
      word_count = cached$word_count[1],
      sentence_count = cached$sentence_count[1],
      from_cache = TRUE
    ))
  }

  # Not cached - calculate now
  doc <- pool::dbGetQuery(pool,
    "SELECT texto_completo FROM documents WHERE id = ?",
    params = list(document_id)
  )

  if (nrow(doc) == 0 || is.na(doc$texto_completo[1])) {
    return(NULL)
  }

  # Calculate metrics
  text <- doc$texto_completo[1]
  metrics <- calculate_all_readability_metrics(text)

  # Count words and sentences
  words <- str_split(text, "\\s+")[[1]]
  words <- str_replace_all(words, "[[:punct:]]", "")
  words <- words[words != ""]

  metrics$word_count <- length(words)
  metrics$sentence_count <- count_sentences(text)

  # Cache the results
  pool::dbExecute(pool,
    "INSERT INTO readability_metrics
     (id, flesch_kincaid, fog_index, smog_index, word_count, sentence_count)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (id) DO UPDATE SET
       flesch_kincaid = EXCLUDED.flesch_kincaid,
       fog_index = EXCLUDED.fog_index,
       smog_index = EXCLUDED.smog_index,
       word_count = EXCLUDED.word_count,
       sentence_count = EXCLUDED.sentence_count,
       calculated_at = CURRENT_TIMESTAMP",
    params = list(
      document_id,
      metrics$flesch_kincaid,
      metrics$fog_index,
      metrics$smog_index,
      metrics$word_count,
      metrics$sentence_count
    )
  )

  metrics$from_cache <- FALSE
  return(metrics)
}

# ==============================================================================
# USAGE NOTES
# ==============================================================================

# To integrate into your app:
#
# 1. Add readability_ui() to your UI where you want the metrics displayed
#
# 2. Call readability_server() in your server function with a reactive
#    expression that returns the document text
#
# 3. For cached metrics, use get_cached_readability() which automatically
#    calculates and stores metrics on first access
#
# 4. For bulk analysis, use the run_readability_analysis.R script to
#    pre-calculate metrics for all documents
#
# 5. Create comparative visualizations using readability_comparison_ui()
#    and readability_comparison_server()
