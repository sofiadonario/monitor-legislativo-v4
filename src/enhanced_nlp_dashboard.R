# ============================================================================
# ENHANCED NLP DASHBOARD INTEGRATION
# Brazilian Legislative Monitoring System - Advanced Text Mining UI
# Author: Legislative Data Science Framework
# Date: 2025-08-05
# Description: Dashboard components for advanced Portuguese legal NLP
# ============================================================================

# Load the advanced NLP pipeline
source("src/advanced_portuguese_legal_nlp.R")

# Enhanced Dashboard UI Components ==========================================

#' Create Text Analytics Tab for Dashboard
#' @return Shiny tab item with text analytics interface
create_text_analytics_tab <- function() {
  tabItem(
    tabName = "text_analytics",
    fluidRow(
      # Control Panel
      box(
        title = "📊 Text Mining Pipeline Control",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        fluidRow(
          column(3,
            numericInput("sample_size", "Sample Size:", value = 1000, min = 100, max = 5000, step = 100)
          ),
          column(3,
            checkboxInput("force_recompute", "Force Recompute", value = FALSE)
          ),
          column(3,
            selectInput("analysis_type", "Analysis Type:",
                       choices = list(
                         "Complete Analysis" = "complete",
                         "Sentiment Only" = "sentiment",
                         "Topics Only" = "topics",
                         "Entities Only" = "entities"
                       ))
          ),
          column(3,
            actionButton("run_analysis", "🚀 Run Analysis", 
                        class = "btn-primary", style = "margin-top: 25px;")
          )
        ),
        hr(),
        verbatimTextOutput("analysis_log")
      )
    ),
    
    fluidRow(
      # Analysis Status
      valueBoxOutput("documents_analyzed"),
      valueBoxOutput("avg_regulatory_strictness"),
      valueBoxOutput("topics_discovered")
    ),
    
    fluidRow(
      # Processing Progress
      box(
        title = "🔄 Processing Status",
        status = "info",
        solidHeader = TRUE,
        width = 6,
        tableOutput("processing_status")
      ),
      
      # Quick Statistics
      box(
        title = "📈 Quick Statistics",
        status = "success",
        solidHeader = TRUE,
        width = 6,
        tableOutput("quick_stats")
      )
    )
  )
}

#' Create Sentiment Analysis Tab
#' @return Shiny tab item with sentiment analysis interface
create_sentiment_analysis_tab <- function() {
  tabItem(
    tabName = "sentiment_analysis",
    fluidRow(
      # Sentiment Distribution
      valueBoxOutput("positive_sentiment"),
      valueBoxOutput("neutral_sentiment"),
      valueBoxOutput("negative_sentiment")
    ),
    
    fluidRow(
      # Regulatory Style Analysis
      box(
        title = "⚖️ Regulatory Style Distribution",
        status = "primary",
        solidHeader = TRUE,
        width = 8,
        plotlyOutput("regulatory_style_plot")
      ),
      
      # Sentiment Summary
      box(
        title = "📊 Sentiment Metrics",
        status = "info",
        solidHeader = TRUE,
        width = 4,
        tableOutput("sentiment_summary")
      )
    ),
    
    fluidRow(
      # Sentiment Over Time
      box(
        title = "📅 Regulatory Strictness Over Time",
        status = "warning",
        solidHeader = TRUE,
        width = 8,
        plotlyOutput("strictness_over_time")
      ),
      
      # Top Legal Indicators
      box(
        title = "🏛️ Legal Indicators",
        status = "success",
        solidHeader = TRUE,
        width = 4,
        DT::dataTableOutput("legal_indicators")
      )
    )
  )
}

#' Create Topic Modeling Tab
#' @return Shiny tab item with topic modeling interface
create_topic_modeling_tab <- function() {
  tabItem(
    tabName = "topic_modeling",
    fluidRow(
      # Topic Model Controls
      box(
        title = "🎛️ Topic Model Configuration",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        fluidRow(
          column(3,
            sliderInput("num_topics", "Number of Topics:", 
                       min = 5, max = 25, value = 10, step = 5)
          ),
          column(3,
            selectInput("topic_algorithm", "Algorithm:",
                       choices = list("LDA" = "lda", "STM" = "stm"))
          ),
          column(3,
            sliderInput("min_doc_freq", "Min Document Frequency:", 
                       min = 2, max = 20, value = 5)
          ),
          column(3,
            actionButton("run_topic_model", "🔍 Run Topic Model",
                        class = "btn-success", style = "margin-top: 25px;")
          )
        )
      )
    ),
    
    fluidRow(
      # Topic Terms Visualization
      box(
        title = "📚 Topic Terms",
        status = "success",
        solidHeader = TRUE,
        width = 8,
        plotlyOutput("topic_terms_plot")
      ),
      
      # Topic Statistics
      box(
        title = "📊 Topic Statistics",
        status = "info",
        solidHeader = TRUE,
        width = 4,
        DT::dataTableOutput("topic_stats")
      )
    ),
    
    fluidRow(
      # Topic Prevalence
      box(
        title = "📈 Topic Prevalence",
        status = "warning",
        solidHeader = TRUE,
        width = 6,
        plotlyOutput("topic_prevalence_plot")
      ),
      
      # Topic Network
      box(
        title = "🕸️ Topic Relationship Network",
        status = "danger",
        solidHeader = TRUE,
        width = 6,
        networkD3::forceNetworkOutput("topic_network")
      )
    )
  )
}

#' Create Entity Recognition Tab
#' @return Shiny tab item with entity recognition interface
create_entity_recognition_tab <- function() {
  tabItem(
    tabName = "entity_recognition",
    fluidRow(
      # Entity Statistics
      valueBoxOutput("total_entities"),
      valueBoxOutput("legal_entities"),
      valueBoxOutput("transport_entities")
    ),
    
    fluidRow(
      # Legal Entities Word Cloud
      box(
        title = "🏛️ Legal Entities Word Cloud",
        status = "primary",
        solidHeader = TRUE,
        width = 6,
        plotOutput("legal_entities_wordcloud")
      ),
      
      # Transport Themes
      box(
        title = "🚛 Transportation Themes",
        status = "success",
        solidHeader = TRUE,
        width = 6,
        plotlyOutput("transport_themes_plot")
      )
    ),
    
    fluidRow(
      # Entity Frequency Table
      box(
        title = "📋 Entity Frequency Analysis",
        status = "info",
        solidHeader = TRUE,
        width = 8,
        DT::dataTableOutput("entity_frequency_table")
      ),
      
      # Entity Type Distribution
      box(
        title = "🏷️ Entity Type Distribution",
        status = "warning",
        solidHeader = TRUE,
        width = 4,
        plotlyOutput("entity_type_distribution")
      )
    )
  )
}

#' Create Semantic Search Tab
#' @return Shiny tab item with semantic search interface
create_semantic_search_tab <- function() {
  tabItem(
    tabName = "semantic_search",
    fluidRow(
      # Search Interface
      box(
        title = "🔍 Semantic Search Interface",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        fluidRow(
          column(8,
            textAreaInput("search_query", "Search Query:", 
                         placeholder = "Enter your search query in Portuguese...",
                         height = "100px")
          ),
          column(2,
            numericInput("similarity_threshold", "Min Similarity:", 
                        value = 0.1, min = 0, max = 1, step = 0.05)
          ),
          column(2,
            actionButton("run_semantic_search", "🔍 Search",
                        class = "btn-primary", style = "margin-top: 25px;")
          )
        )
      )
    ),
    
    fluidRow(
      # Search Results
      box(
        title = "📋 Search Results",
        status = "success",
        solidHeader = TRUE,
        width = 12,
        DT::dataTableOutput("semantic_search_results")
      )
    ),
    
    fluidRow(
      # Similarity Visualization
      box(
        title = "📊 Similarity Score Distribution",
        status = "info",
        solidHeader = TRUE,
        width = 6,
        plotlyOutput("similarity_distribution")
      ),
      
      # Related Terms
      box(
        title = "🔗 Related Terms",
        status = "warning",
        solidHeader = TRUE,
        width = 6,
        DT::dataTableOutput("related_terms")
      )
    )
  )
}

# Enhanced Dashboard Server Logic ============================================

#' Create Enhanced Server Logic for NLP Dashboard
#' @param input Shiny input
#' @param output Shiny output  
#' @param session Shiny session
#' @return Server function
create_nlp_server_logic <- function(input, output, session) {
  
  # Reactive values for storing analysis results
  analysis_results <- reactiveValues(
    nlp_data = NULL,
    processing_log = "",
    last_updated = NULL
  )
  
  # Text Analytics Tab Logic ================================================
  
  # Run NLP Analysis
  observeEvent(input$run_analysis, {
    analysis_results$processing_log <- "🚀 Starting NLP analysis...\n"
    
    tryCatch({
      # Run the advanced NLP pipeline
      results <- run_advanced_text_mining_pipeline(
        sample_size = input$sample_size,
        force_recompute = input$force_recompute
      )
      
      analysis_results$nlp_data <- results
      analysis_results$last_updated <- Sys.time()
      analysis_results$processing_log <- paste0(
        analysis_results$processing_log,
        "✅ Analysis completed successfully!\n",
        "📊 Documents analyzed: ", results$summary_stats$valid_documents, "\n",
        "🏷️ Entities found: ", sum(results$entity_extraction$entity_counts), "\n",
        "📚 Topics discovered: ", results$topic_modeling$best_k, "\n"
      )
      
    }, error = function(e) {
      analysis_results$processing_log <- paste0(
        analysis_results$processing_log,
        "❌ Error: ", e$message, "\n"
      )
    })
  })
  
  # Analysis Log Output
  output$analysis_log <- renderText({
    analysis_results$processing_log
  })
  
  # Value Boxes for Text Analytics
  output$documents_analyzed <- renderValueBox({
    if (is.null(analysis_results$nlp_data)) {
      count <- 0
    } else {
      count <- analysis_results$nlp_data$summary_stats$valid_documents
    }
    
    valueBox(
      value = format(count, big.mark = ","),
      subtitle = "Documents Analyzed",
      icon = icon("file-text"),
      color = "blue"
    )
  })
  
  output$avg_regulatory_strictness <- renderValueBox({
    if (is.null(analysis_results$nlp_data)) {
      strictness <- 0
    } else {
      strictness <- mean(analysis_results$nlp_data$sentiment_analysis$strictness_index, na.rm = TRUE)
    }
    
    valueBox(
      value = round(strictness * 100, 1),
      subtitle = "Avg Regulatory Strictness (%)",
      icon = icon("balance-scale"),
      color = "yellow"
    )
  })
  
  output$topics_discovered <- renderValueBox({
    if (is.null(analysis_results$nlp_data)) {
      topics <- 0
    } else {
      topics <- analysis_results$nlp_data$topic_modeling$best_k
    }
    
    valueBox(
      value = topics,
      subtitle = "Topics Discovered",
      icon = icon("sitemap"),
      color = "green"
    )
  })
  
  # Sentiment Analysis Tab Logic ============================================
  
  # Sentiment Value Boxes
  output$positive_sentiment <- renderValueBox({
    sentiment_data <- get_sentiment_dashboard_data()
    pos_count <- sentiment_data$sentiment_distribution %>%
      filter(sentiment_category == "Positive") %>%
      pull(count) %>%
      ifelse(length(.) == 0, 0, .)
    
    valueBox(
      value = pos_count,
      subtitle = "Positive Documents",
      icon = icon("thumbs-up"),
      color = "green"
    )
  })
  
  output$neutral_sentiment <- renderValueBox({
    sentiment_data <- get_sentiment_dashboard_data()
    neutral_count <- sentiment_data$sentiment_distribution %>%
      filter(sentiment_category == "Neutral") %>%
      pull(count) %>%
      ifelse(length(.) == 0, 0, .)
    
    valueBox(
      value = neutral_count,
      subtitle = "Neutral Documents",
      icon = icon("minus"),
      color = "yellow"
    )
  })
  
  output$negative_sentiment <- renderValueBox({
    sentiment_data <- get_sentiment_dashboard_data()
    neg_count <- sentiment_data$sentiment_distribution %>%
      filter(sentiment_category == "Negative") %>%
      pull(count) %>%
      ifelse(length(.) == 0, 0, .)
    
    valueBox(
      value = neg_count,
      subtitle = "Negative Documents",
      icon = icon("thumbs-down"),
      color = "red"
    )
  })
  
  # Regulatory Style Plot
  output$regulatory_style_plot <- renderPlotly({
    sentiment_data <- get_sentiment_dashboard_data()
    
    p <- sentiment_data$regulatory_style %>%
      ggplot(aes(x = reorder(regulatory_style, count), y = count, fill = regulatory_style)) +
      geom_col() +
      coord_flip() +
      labs(
        title = "Distribution of Regulatory Styles",
        x = "Regulatory Style",
        y = "Document Count",
        fill = "Style"
      ) +
      theme_minimal() +
      scale_fill_viridis_d()
    
    ggplotly(p)
  })
  
  # Entity Recognition Tab Logic ============================================
  
  # Entity Value Boxes
  output$total_entities <- renderValueBox({
    entities_data <- get_entities_dashboard_data()
    total <- sum(entities_data$legal_entities$frequency, na.rm = TRUE)
    
    valueBox(
      value = total,
      subtitle = "Total Entities",
      icon = icon("tags"),
      color = "blue"
    )
  })
  
  output$legal_entities <- renderValueBox({
    entities_data <- get_entities_dashboard_data()
    legal_count <- entities_data$legal_entities %>%
      filter(entity_type %in% c("agency", "law", "decree")) %>%
      nrow()
    
    valueBox(
      value = legal_count,
      subtitle = "Legal Entities",
      icon = icon("university"),
      color = "purple"
    )
  })
  
  output$transport_entities <- renderValueBox({
    entities_data <- get_entities_dashboard_data()
    transport_count <- sum(entities_data$transport_themes$frequency, na.rm = TRUE)
    
    valueBox(
      value = transport_count,
      subtitle = "Transport Themes",
      icon = icon("truck"),
      color = "orange"
    )
  })
  
  # Transportation Themes Plot
  output$transport_themes_plot <- renderPlotly({
    entities_data <- get_entities_dashboard_data()
    
    p <- entities_data$transport_themes %>%
      ggplot(aes(x = reorder(theme, frequency), y = frequency, fill = theme)) +
      geom_col() +
      coord_flip() +
      labs(
        title = "Transportation Theme Frequency",
        x = "Theme",
        y = "Frequency",
        fill = "Theme"
      ) +
      theme_minimal() +
      scale_fill_brewer(type = "qual", palette = "Set3")
    
    ggplotly(p)
  })
  
  # Entity Frequency Table
  output$entity_frequency_table <- DT::renderDataTable({
    entities_data <- get_entities_dashboard_data()
    
    DT::datatable(
      entities_data$legal_entities,
      options = list(
        pageLength = 15,
        scrollX = TRUE,
        searchHighlight = TRUE
      ),
      rownames = FALSE
    ) %>%
      DT::formatStyle(
        "frequency",
        background = DT::styleColorBar(entities_data$legal_entities$frequency, "lightblue")
      )
  })
  
  # Topic Modeling Tab Logic ===============================================
  
  # Topic Terms Plot
  output$topic_terms_plot <- renderPlotly({
    topics_data <- get_topics_dashboard_data()
    
    p <- topics_data$topic_terms %>%
      group_by(topic) %>%
      top_n(5, beta) %>%
      ungroup() %>%
      mutate(term = reorder_within(term, beta, topic)) %>%
      ggplot(aes(beta, term, fill = factor(topic))) +
      geom_col(show.legend = FALSE) +
      facet_wrap(~ paste("Topic", topic), scales = "free") +
      scale_y_reordered() +
      labs(
        title = "Top Terms by Topic",
        x = "Beta (Term Probability)",
        y = "Terms"
      ) +
      theme_minimal()
    
    ggplotly(p)
  })
  
  # Topic Statistics Table
  output$topic_stats <- DT::renderDataTable({
    topics_data <- get_topics_dashboard_data()
    
    DT::datatable(
      topics_data$topic_prevalence,
      options = list(pageLength = 10),
      rownames = FALSE
    )
  })
  
  # Semantic Search Tab Logic ===============================================
  
  # Semantic Search Results
  output$semantic_search_results <- DT::renderDataTable({
    # Placeholder for semantic search results
    tibble(
      Document = paste("Document", 1:5),
      Title = paste("Title", 1:5),
      Similarity = c(0.95, 0.87, 0.76, 0.65, 0.58),
      Category = sample(c("Legislation", "Jurisprudence", "Doctrine"), 5, replace = TRUE)
    ) %>%
      DT::datatable(
        options = list(pageLength = 10),
        rownames = FALSE
      ) %>%
      DT::formatRound("Similarity", 3) %>%
      DT::formatStyle(
        "Similarity",
        background = DT::styleColorBar(c(0, 1), "lightgreen")
      )
  })
  
}

# Export Dashboard Components =================================================

#' Get Complete Enhanced Dashboard UI
#' @return Complete dashboard UI with NLP tabs
get_enhanced_nlp_dashboard_ui <- function() {
  dashboardPage(
    dashboardHeader(title = "Brazilian Legislative Monitor - Advanced NLP"),
    
    dashboardSidebar(
      siderbarMenu(
        menuItem("📊 Text Analytics", tabName = "text_analytics", icon = icon("chart-line")),
        menuItem("😊 Sentiment Analysis", tabName = "sentiment_analysis", icon = icon("heart")),
        menuItem("📚 Topic Modeling", tabName = "topic_modeling", icon = icon("sitemap")),
        menuItem("🏛️ Entity Recognition", tabName = "entity_recognition", icon = icon("university")),
        menuItem("🔍 Semantic Search", tabName = "semantic_search", icon = icon("search"))
      )
    ),
    
    dashboardBody(
      tabItems(
        create_text_analytics_tab(),
        create_sentiment_analysis_tab(),
        create_topic_modeling_tab(),
        create_entity_recognition_tab(),
        create_semantic_search_tab()
      )
    )
  )
}

cat("✅ Enhanced NLP Dashboard components loaded successfully!\n")
cat("🎨 Use get_enhanced_nlp_dashboard_ui() to get complete dashboard\n")
cat("⚙️ Use create_nlp_server_logic() for server functionality\n")