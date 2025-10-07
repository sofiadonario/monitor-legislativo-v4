# ============================================================================
# ANALYTICS SERVER LOGIC
# ============================================================================
# 
# Shiny server logic for advanced analytics dashboard
# Integrates with Railway-optimized backend
# 
# Author: Data Science Consultant
# Date: 2025-08-19
# Version: 4.0 Production
# ============================================================================

# ============================================================================
# ANALYTICS SERVER FUNCTION
# ============================================================================

#' Analytics server logic for Shiny application
#' 
#' @param input Shiny input object
#' @param output Shiny output object  
#' @param session Shiny session object
#' @param get_data Function to retrieve data
analytics_server <- function(input, output, session, get_data) {
  
  cat("🔧 Initializing analytics server logic...\n")
  
  # Reactive values for analytics results
  analytics_results <- reactiveVal(NULL)
  performance_metrics <- reactiveVal(NULL)
  
  # ============================================================================
  # VALUE BOXES
  # ============================================================================
  
  # Total documents value box
  output$analytics_total_docs <- renderValueBox({
    results <- analytics_results()
    require_rows(results, "Sem dados analíticos")
    value_boxes <- create_analytics_value_boxes(results)
    safe_valueBox(value_boxes$total_docs$value %||% "—", "Documentos", icon = icon("file"))
  })
  
  # Temporal coverage value box
  output$analytics_temporal_coverage <- renderValueBox({
    tryCatch({
      results <- analytics_results()
      value_boxes <- create_analytics_value_boxes(results)
      value_boxes$temporal_coverage %||% safe_valueBox("—", "Cobertura", icon = icon("calendar"))
    }, error = function(e) {
      if (identical(Sys.getenv("APP_DEBUG"), "1")) diag_log_error(e, "analytics_temporal_coverage")
      safe_valueBox("—", "Cobertura", icon = icon("calendar"))
    })
  })
  
  # Processing status value box
  output$analytics_processing_status <- renderValueBox({
    tryCatch({
      results <- analytics_results()
      value_boxes <- create_analytics_value_boxes(results)
      value_boxes$processing_status %||% safe_valueBox("—", "Status", icon = icon("clock"))
    }, error = function(e) {
      if (identical(Sys.getenv("APP_DEBUG"), "1")) diag_log_error(e, "analytics_processing_status")
      safe_valueBox("—", "Status", icon = icon("clock"))
    })
  })

  # Data quality value box
  output$analytics_data_quality <- renderValueBox({
    tryCatch({
      results <- analytics_results()
      value_boxes <- create_analytics_value_boxes(results)
      value_boxes$data_quality %||% safe_valueBox("—", "Qualidade", icon = icon("check-circle"))
    }, error = function(e) {
      if (identical(Sys.getenv("APP_DEBUG"), "1")) diag_log_error(e, "analytics_data_quality")
      safe_valueBox("—", "Qualidade", icon = icon("check-circle"))
    })
  })
  
  # ============================================================================
  # MAIN ANALYTICS EXECUTION
  # ============================================================================
  
  # Execute comprehensive analytics
  observeEvent(input$run_analytics, {
    
    cat("🚀 Starting comprehensive analytics execution...\n")
    
    # Show loading message
    showModal(modalDialog(
      title = "🔄 Executando Análise Completa",
      "Por favor aguarde. A análise está sendo processada...",
      tags$br(),
      tags$div(
        style = "text-align: center;",
        tags$div(class = "spinner-border", role = "status"),
        tags$p("Isto pode levar alguns minutos.")
      ),
      footer = NULL,
      easyClose = FALSE
    ))
    
    tryCatch({
      # Get current data
      current_data <- get_data()
      
      if (is.null(current_data) || nrow(current_data) == 0) {
        removeModal()
        showNotification(
          "❌ Nenhum dado disponível para análise. Verifique a conexão com o banco de dados.",
          type = "error",
          duration = 5
        )
        return()
      }
      
      # Record start time for performance monitoring
      start_time <- Sys.time()
      
      # Get analysis parameters from UI
      analysis_types <- input$analytics_analysis_types
      max_docs <- input$analytics_max_documents
      railway_mode <- input$analytics_railway_optimization
      
      if (length(analysis_types) == 0) {
        analysis_types <- c("temporal", "productivity")
      }
      
      cat("📊 Running analytics with parameters:\n")
      cat("   Analysis types:", paste(analysis_types, collapse = ", "), "\n")
      cat("   Max documents:", max_docs, "\n")
      cat("   Railway mode:", railway_mode, "\n")
      
      # Run comprehensive analytics
      results <- run_comprehensive_analytics(
        data = current_data,
        analysis_type = analysis_types,
        railway_optimized = railway_mode,
        max_documents = max_docs
      )
      
      # Monitor performance
      perf_metrics <- monitor_analytics_performance(
        start_time = start_time,
        data_size = nrow(current_data),
        analysis_types = analysis_types
      )
      
      # Store results
      analytics_results(results)
      performance_metrics(perf_metrics)
      
      # Remove loading modal
      removeModal()
      
      # Show success notification
      if ("error" %in% names(results)) {
        showNotification(
          paste("⚠️ Análise concluída com avisos:", results$error),
          type = "warning",
          duration = 5
        )
      } else {
        showNotification(
          "✅ Análise completa executada com sucesso!",
          type = "success",
          duration = 3
        )
      }
      
      # Update UI sections
      update_analytics_ui(results)
      
    }, error = function(e) {
      removeModal()
      cat("❌ Error in analytics execution:", e$message, "\n")
      
      showNotification(
        paste("❌ Erro na execução da análise:", e$message),
        type = "error",
        duration = 10
      )
    })
  })
  
  # ============================================================================
  # UI UPDATE FUNCTIONS
  # ============================================================================
  
  # Update analytics UI sections with results
  update_analytics_ui <- function(results) {
    
    tryCatch({
      # Update executive summary sections
      output$analytics_key_findings <- renderUI({
        format_analytics_for_ui(results, "summary")
      })
      
      output$analytics_recommendations <- renderUI({
        format_analytics_for_ui(results, "recommendations")
      })
      
      output$analytics_data_quality <- renderUI({
        format_analytics_for_ui(results, "data_quality")
      })
      
      # Update temporal analysis section
      if ("temporal_analysis" %in% names(results) && !("error" %in% names(results$temporal_analysis))) {
        update_temporal_analysis_ui(results$temporal_analysis)
      }
      
      # Update categorization section
      if ("categorization_analysis" %in% names(results) && !("error" %in% names(results$categorization_analysis))) {
        update_categorization_ui(results$categorization_analysis)
      }
      
      # Update legal context section
      if ("legal_context_analysis" %in% names(results) && !("error" %in% names(results$legal_context_analysis))) {
        update_legal_context_ui(results$legal_context_analysis)
      }
      
      # Update productivity section
      if ("productivity_analysis" %in% names(results) && !("error" %in% names(results$productivity_analysis))) {
        update_productivity_ui(results$productivity_analysis)
      }
      
      # Update impact assessment section
      if ("impact_analysis" %in% names(results) && !("error" %in% names(results$impact_analysis))) {
        update_impact_ui(results$impact_analysis)
      }
      
      # Update performance monitoring
      perf <- performance_metrics()
      if (!is.null(perf)) {
        update_performance_ui(perf)
      }
      
    }, error = function(e) {
      cat("⚠️ Error updating analytics UI:", e$message, "\n")
    })
  }
  
  # ============================================================================
  # TEMPORAL ANALYSIS UPDATES
  # ============================================================================
  
  update_temporal_analysis_ui <- function(temporal_results) {
    
    # Temporal trend plot
    output$temporal_trend_plot <- safe_renderPlotly({
      if ("temporal_summary" %in% names(temporal_results) && has_rows(temporal_results$temporal_summary)) {
        
        temporal_data <- temporal_results$temporal_summary
        
        p <- ggplot(temporal_data, aes(x = year, y = document_count)) +
          geom_line(color = "#2E86AB", size = 1.2) +
          geom_point(color = "#A23B72", size = 2) +
          geom_smooth(method = "loess", se = TRUE, alpha = 0.3, color = "#F18F01") +
          labs(
            title = "Evolução Temporal da Produção Legislativa Brasileira",
            subtitle = paste("Período:", min(temporal_data$year), "-", max(temporal_data$year)),
            x = "Ano",
            y = "Número de Documentos"
          ) +
          theme_minimal() +
          theme(
            plot.title = element_text(size = 14, face = "bold"),
            plot.subtitle = element_text(size = 12),
            axis.text = element_text(size = 10)
          ) +
          scale_x_continuous(breaks = scales::pretty_breaks(n = 10)) +
          scale_y_continuous(labels = scales::comma_format())
        
        ggplotly(p, tooltip = c("x", "y")) %>%
          layout(
            hovermode = "x unified",
            showlegend = FALSE
          )
        
      } else {
        plotly::plot_ly() %>%
          layout(
            title = "Dados de tendência temporal não disponíveis",
            annotations = list(
              text = "Execute a análise temporal para ver os resultados",
              showarrow = FALSE
            )
          )
      }
    }, context = "analytics$temporal_trend_plot")
    
    # Temporal metrics
    output$temporal_metrics <- safe_renderUI({
      if ("productivity_metrics" %in% names(temporal_results)) {
        metrics <- temporal_results$productivity_metrics
        
        tags$div(
          if ("peak_analysis" %in% names(metrics)) {
            tags$div(
              tags$p(tags$strong("🏆 Pico de Produtividade:"), 
                    metrics$peak_analysis$highest_productivity$period_label,
                    " (", metrics$peak_analysis$highest_productivity$document_count, " documentos)"),
              tags$p(tags$strong("📉 Menor Produtividade:"), 
                    metrics$peak_analysis$lowest_productivity$period_label,
                    " (", metrics$peak_analysis$lowest_productivity$document_count, " documentos)")
            )
          },
          
          if ("growth_analysis" %in% names(metrics)) {
            tags$div(
              tags$p(tags$strong("📈 Taxa de Crescimento Média:"), 
                    paste0(round(metrics$growth_analysis$avg_growth_rate, 2), "%")),
              tags$p(tags$strong("📊 Volatilidade:"), 
                    round(metrics$growth_analysis$volatility, 2))
            )
          }
        )
        
      } else {
        tags$p("Métricas temporais não disponíveis")
      }
    }, context = "analytics$temporal_metrics")
    
    # Historical context
    output$historical_context <- renderUI({
      
      if ("historical_context" %in% names(temporal_results) && 
          "major_legislative_eras" %in% names(temporal_results$historical_context)) {
        
        eras <- temporal_results$historical_context$major_legislative_eras
        
        tags$div(
          tags$h5("🏛️ Eras Legislativas Brasileiras"),
          lapply(1:min(5, nrow(eras)), function(i) {
            era <- eras[i, ]
            tags$p(
              tags$strong(era$era_label), ": ",
              format(era$total_documents, big.mark = ","), " documentos"
            )
          })
        )
        
      } else {
        tags$p("Contexto histórico não disponível")
      }
    })
  }
  
  # ============================================================================
  # CATEGORIZATION UPDATES
  # ============================================================================
  
  update_categorization_ui <- function(categorization_results) {
    
    # Categorization plot
    output$categorization_plot <- renderPlotly({
      
      if ("categorization_summary" %in% names(categorization_results) &&
          "legal_type_distribution" %in% names(categorization_results$categorization_summary)) {
        
        cat_data <- categorization_results$categorization_summary$legal_type_distribution
        
        if (!is.null(cat_data) && is.data.frame(cat_data) && nrow(cat_data) > 0) {
          
          # Limit to top 10 categories for readability
          cat_data <- cat_data %>% head(10)
          
          p <- ggplot(cat_data, aes(x = reorder(legal_type, n), y = n)) +
            geom_col(fill = "#F18F01", alpha = 0.8) +
            coord_flip() +
            labs(
              title = "Distribuição por Tipo de Documento Legal",
              subtitle = "Top 10 categorias mais frequentes",
              x = "Tipo de Documento",
              y = "Quantidade"
            ) +
            theme_minimal() +
            scale_y_continuous(labels = scales::comma_format())
          
          ggplotly(p, tooltip = c("y")) %>%
            layout(
              margin = list(l = 150),  # More space for category names
              showlegend = FALSE
            )
          
        } else {
          plotly::plot_ly() %>%
            layout(title = "Dados de categorização não disponíveis")
        }
        
      } else {
        plotly::plot_ly() %>%
          layout(title = "Execute a análise de categorização")
      }
    })
    
    # Categorization statistics
    output$categorization_stats <- renderUI({
      
      if ("categorization_summary" %in% names(categorization_results)) {
        summary <- categorization_results$categorization_summary
        
        tags$div(
          tags$p(tags$strong("📊 Total Categorizado:"), 
                format(summary$categorized_documents, big.mark = ",")),
          tags$p(tags$strong("📈 Cobertura:"), 
                paste0(round(summary$coverage_percentage, 1), "%")),
          
          if ("confidence_stats" %in% names(summary)) {
            tags$div(
              tags$hr(),
              tags$h5("🎯 Confiança da Categorização"),
              tags$p(tags$strong("Confiança Média:"), 
                    round(summary$confidence_stats$mean_confidence, 3)),
              tags$p(tags$strong("Alta Confiança:"), 
                    summary$confidence_stats$high_confidence_docs, " docs"),
              tags$p(tags$strong("Baixa Confiança:"), 
                    summary$confidence_stats$low_confidence_docs, " docs")
            )
          }
        )
        
      } else {
        tags$p("Estatísticas de categorização não disponíveis")
      }
    })
    
    # Cross-references table
    output$cross_references_table <- DT::renderDataTable({
      
      if ("cross_references" %in% names(categorization_results) &&
          "citation_network" %in% names(categorization_results$cross_references)) {
        
        citations <- categorization_results$cross_references$citation_network
        
        if (!is.null(citations) && is.data.frame(citations) && nrow(citations) > 0) {
          display_data <- citations %>%
            select(citations, frequency) %>%
            arrange(desc(frequency)) %>%
            head(20)
          
          names(display_data) <- c("Citação Legal", "Frequência")
          
          create_analytics_table(display_data, "Top 20 Citações Mais Frequentes")
          
        } else {
          create_analytics_table(NULL, "Referências Cruzadas")
        }
        
      } else {
        create_analytics_table(NULL, "Referências Cruzadas")
      }
    })
  }
  
  # ============================================================================
  # LEGAL CONTEXT UPDATES
  # ============================================================================
  
  update_legal_context_ui <- function(legal_context_results) {
    
    # Federal system plot
    output$federal_system_plot <- renderPlotly({
      
      if ("federal_system_analysis" %in% names(legal_context_results) &&
          "authority_distribution" %in% names(legal_context_results$federal_system_analysis)) {
        
        authority_data <- legal_context_results$federal_system_analysis$authority_distribution
        
        if (!is.null(authority_data) && is.data.frame(authority_data) && nrow(authority_data) > 0) {
          
          p <- ggplot(authority_data, aes(x = reorder(authority_level, percentage), y = percentage)) +
            geom_col(fill = c("#2E86AB", "#A23B72", "#F18F01", "#C73E1D")[1:nrow(authority_data)]) +
            coord_flip() +
            labs(
              title = "Distribuição por Nível de Autoridade",
              x = "Nível de Autoridade",
              y = "Porcentagem (%)"
            ) +
            theme_minimal()
          
          ggplotly(p, tooltip = c("y")) %>%
            layout(showlegend = FALSE)
          
        } else {
          plotly::plot_ly() %>%
            layout(title = "Dados do sistema federativo não disponíveis")
        }
        
      } else {
        plotly::plot_ly() %>%
          layout(title = "Execute a análise de contexto legal")
      }
    })
    
    # Transport framework
    output$transport_framework <- renderUI({
      
      if ("transport_analysis" %in% names(legal_context_results)) {
        transport <- legal_context_results$transport_analysis
        
        tags$div(
          if ("framework_coverage" %in% names(transport) && nrow(transport$framework_coverage) > 0) {
            tags$div(
              tags$h5("📋 Marcos Regulatórios Identificados"),
              lapply(1:min(5, nrow(transport$framework_coverage)), function(i) {
                framework <- transport$framework_coverage[i, ]
                tags$p(tags$strong(framework$transport_framework), ": ", 
                      framework$n, " documentos")
              })
            )
          },
          
          if ("regulatory_agencies" %in% names(transport)) {
            tags$div(
              tags$hr(),
              tags$h5("🏛️ Agências Reguladoras"),
              tags$p("ANTT:", transport$regulatory_agencies$antt_mentions, " menções"),
              tags$p("ANTAQ:", transport$regulatory_agencies$antaq_mentions, " menções"),
              tags$p("ANAC:", transport$regulatory_agencies$anac_mentions, " menções")
            )
          }
        )
        
      } else {
        tags$p("Análise do marco regulatório não disponível")
      }
    })
    
    # Constitutional evolution
    output$constitutional_evolution <- renderUI({
      
      if ("constitutional_analysis" %in% names(legal_context_results)) {
        const_analysis <- legal_context_results$constitutional_analysis
        
        tags$div(
          tags$h5("⚖️ Menções Constitucionais"),
          if ("constitutional_mentions" %in% names(const_analysis)) {
            tags$div(
              tags$p("Constituição Federal:", const_analysis$constitutional_mentions$cf88_mentions, " menções"),
              tags$p("Devido Processo Legal:", const_analysis$constitutional_mentions$due_process, " menções"),
              tags$p("Princípio da Eficiência:", const_analysis$constitutional_mentions$efficiency, " menções")
            )
          },
          
          if ("fundamental_rights" %in% names(const_analysis)) {
            tags$p(tags$strong("Direitos Fundamentais:"), const_analysis$fundamental_rights, " documentos")
          }
        )
        
      } else {
        tags$p("Análise constitucional não disponível")
      }
    })
  }
  
  # ============================================================================
  # PRODUCTIVITY UPDATES
  # ============================================================================
  
  update_productivity_ui <- function(productivity_results) {
    
    # Productivity plot
    output$productivity_plot <- renderPlotly({
      
      if ("productivity_summary" %in% names(productivity_results)) {
        
        prod_data <- productivity_results$productivity_summary
        
        if (!is.null(prod_data) && is.data.frame(prod_data) && nrow(prod_data) > 0) {
          
          # Handle different time period formats
          if ("year" %in% names(prod_data)) {
            x_var <- "year"
            title_text <- "Produtividade Legislativa por Ano"
          } else if ("period_label" %in% names(prod_data)) {
            x_var <- "period_label"
            title_text <- "Produtividade Legislativa por Período"
          } else {
            x_var <- names(prod_data)[1]
            title_text <- "Produtividade Legislativa"
          }
          
          p <- ggplot(prod_data, aes_string(x = x_var, y = "document_count")) +
            geom_line(color = "#2E86AB", size = 1.2, group = 1) +
            geom_point(color = "#A23B72", size = 2) +
            labs(
              title = title_text,
              x = "Período",
              y = "Número de Documentos"
            ) +
            theme_minimal() +
            scale_y_continuous(labels = scales::comma_format())
          
          # Rotate x-axis labels if needed
          if (!is.null(prod_data) && is.data.frame(prod_data) && nrow(prod_data) > 10) {
            p <- p + theme(axis.text.x = element_text(angle = 45, hjust = 1))
          }
          
          ggplotly(p, tooltip = c("x", "y")) %>%
            layout(showlegend = FALSE)
          
        } else {
          plotly::plot_ly() %>%
            layout(title = "Dados de produtividade não disponíveis")
        }
        
      } else {
        plotly::plot_ly() %>%
          layout(title = "Execute a análise de produtividade")
      }
    })
    
    # Efficiency metrics
    output$efficiency_metrics <- renderUI({
      
      if ("efficiency_metrics" %in% names(productivity_results)) {
        metrics <- productivity_results$efficiency_metrics
        
        tags$div(
          tags$p(tags$strong("📊 Produção Anual Média:"), 
                round(metrics$average_annual_output, 0), " documentos"),
          tags$p(tags$strong("🌍 Cobertura Geográfica:"), 
                metrics$geographic_coverage, " estados"),
          tags$p(tags$strong("📋 Categorias Cobertas:"), 
                metrics$category_coverage),
          tags$p(tags$strong("🎯 Score de Consistência:"), 
                round(metrics$consistency_score, 3))
        )
        
      } else {
        tags$p("Métricas de eficiência não disponíveis")
      }
    })
    
    # Peak periods
    output$peak_periods <- renderUI({
      
      if ("productivity_metrics" %in% names(productivity_results) &&
          "peak_analysis" %in% names(productivity_results$productivity_metrics)) {
        
        peak_analysis <- productivity_results$productivity_metrics$peak_analysis
        
        tags$div(
          tags$p(tags$strong("🏆 Maior Produtividade:"), 
                peak_analysis$highest_productivity$period_label,
                " (", peak_analysis$highest_productivity$document_count, " docs)"),
          tags$p(tags$strong("📈 Tendência:"), 
                str_to_title(peak_analysis$productivity_trend)),
          tags$p(tags$strong("📊 Períodos Acima da Média:"), 
                peak_analysis$above_average_periods)
        )
        
      } else {
        tags$p("Análise de picos não disponível")
      }
    })
    
    # Growth trends
    output$growth_trends <- renderUI({
      
      if ("productivity_metrics" %in% names(productivity_results) &&
          "growth_analysis" %in% names(productivity_results$productivity_metrics)) {
        
        growth <- productivity_results$productivity_metrics$growth_analysis
        
        tags$div(
          tags$p(tags$strong("📈 Crescimento Total:"), 
                paste0(round(growth$total_growth, 1), "%")),
          tags$p(tags$strong("📊 Taxa Média de Crescimento:"), 
                paste0(round(growth$avg_growth_rate, 2), "%")),
          tags$p(tags$strong("📉 Coeficiente de Variação:"), 
                round(growth$coefficient_of_variation, 3))
        )
        
      } else {
        tags$p("Análise de crescimento não disponível")
      }
    })
  }
  
  # ============================================================================
  # IMPACT ASSESSMENT UPDATES
  # ============================================================================
  
  update_impact_ui <- function(impact_results) {
    
    # Economic impact
    output$economic_impact <- renderUI({
      
      if ("economic_impact" %in% names(impact_results)) {
        economic <- impact_results$economic_impact
        
        tags$div(
          if ("economic_stats" %in% names(economic)) {
            tags$div(
              tags$p(tags$strong("💰 Documentos com Impacto Econômico:"), 
                    economic$economic_stats$total_documents_with_economic_impact),
              tags$p(tags$strong("📊 Cobertura Econômica:"), 
                    paste0(round(economic$economic_stats$economic_coverage, 1), "%")),
              tags$p(tags$strong("🎯 Indicador Mais Afetado:"), 
                    economic$economic_stats$most_affected_indicator)
            )
          }
        )
        
      } else {
        tags$p("Análise de impacto econômico não disponível")
      }
    })
    
    # Social impact
    output$social_impact <- renderUI({
      
      if ("social_impact" %in% names(impact_results)) {
        social <- impact_results$social_impact
        
        tags$div(
          if ("social_stats" %in% names(social)) {
            tags$div(
              tags$p(tags$strong("👥 Documentos com Impacto Social:"), 
                    social$social_stats$documents_with_social_impact),
              tags$p(tags$strong("📊 Cobertura Social:"), 
                    paste0(round(social$social_stats$social_coverage, 1), "%")),
              tags$p(tags$strong("🎯 Área Social Mais Afetada:"), 
                    social$social_stats$most_affected_social_area)
            )
          }
        )
        
      } else {
        tags$p("Análise de impacto social não disponível")
      }
    })
    
    # Environmental impact
    output$environmental_impact <- renderUI({
      
      if ("environmental_impact" %in% names(impact_results)) {
        environmental <- impact_results$environmental_impact
        
        tags$div(
          if ("environmental_stats" %in% names(environmental)) {
            tags$div(
              tags$p(tags$strong("🌱 Documentos com Impacto Ambiental:"), 
                    environmental$environmental_stats$documents_with_environmental_impact),
              tags$p(tags$strong("📊 Cobertura Ambiental:"), 
                    paste0(round(environmental$environmental_stats$environmental_coverage, 1), "%")),
              tags$p(tags$strong("🎯 Área Ambiental Crítica:"), 
                    environmental$environmental_stats$most_critical_environmental_area)
            )
          }
        )
        
      } else {
        tags$p("Análise de impacto ambiental não disponível")
      }
    })
    
    # High impact documents table
    output$high_impact_documents <- DT::renderDataTable({
      
      if ("comprehensive_synthesis" %in% names(impact_results) &&
          "high_impact_documents" %in% names(impact_results$comprehensive_synthesis)) {
        
        high_impact <- impact_results$comprehensive_synthesis$high_impact_documents
        
        if (!is.null(high_impact) && is.data.frame(high_impact) && nrow(high_impact) > 0) {
          
          display_data <- high_impact %>%
            select(title, total_impact_score, year, state) %>%
            head(20)
          
          names(display_data) <- c("Título", "Score de Impacto", "Ano", "Estado")
          
          create_analytics_table(display_data, "Documentos de Alto Impacto Regulatório")
          
        } else {
          create_analytics_table(NULL, "Documentos de Alto Impacto")
        }
        
      } else {
        create_analytics_table(NULL, "Documentos de Alto Impacto")
      }
    })
  }
  
  # ============================================================================
  # PERFORMANCE MONITORING UPDATES
  # ============================================================================
  
  update_performance_ui <- function(perf_metrics) {
    
    # Performance metrics
    output$performance_metrics <- renderUI({
      
      tags$div(
        tags$p(tags$strong("⏱️ Tempo de Execução:"), 
              paste0(round(perf_metrics$execution_time_seconds, 2), " segundos")),
        tags$p(tags$strong("📊 Documentos Processados:"), 
              format(perf_metrics$documents_processed, big.mark = ",")),
        tags$p(tags$strong("🚀 Taxa de Processamento:"), 
              paste0(round(perf_metrics$processing_rate, 1), " docs/segundo")),
        tags$p(tags$strong("🔧 Análises Completadas:"), 
              perf_metrics$analyses_completed)
      )
    })
    
    # Railway compatibility
    output$railway_compatibility <- renderUI({
      
      railway_compat <- perf_metrics$railway_compatibility
      
      tags$div(
        tags$p(tags$strong("⏰ Dentro do Limite de Tempo:"), 
              if(railway_compat$within_time_limit) "✅ Sim" else "❌ Não"),
        tags$p(tags$strong("💾 Dentro do Limite de Memória:"), 
              if(railway_compat$within_memory_limit) "✅ Sim" else "❌ Não"),
        tags$p(tags$strong("🔧 Otimização Aplicada:"), 
              if(railway_compat$optimization_applied) "✅ Sim" else "❌ Não")
      )
    })
  }
  
  # ============================================================================
  # EXPORT FUNCTIONALITY
  # ============================================================================
  
  observeEvent(input$export_analytics, {
    
    results <- analytics_results()
    
    if (is.null(results)) {
      showNotification(
        "⚠️ Nenhum resultado de análise disponível para exportar.",
        type = "warning",
        duration = 3
      )
      return()
    }
    
    tryCatch({
      
      # Prepare export data
      export_timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
      export_filename <- paste0("analytics_export_", export_timestamp, ".rds")
      
      # Save results
      saveRDS(results, file = export_filename)
      
      showNotification(
        paste("✅ Resultados exportados para:", export_filename),
        type = "success",
        duration = 5
      )
      
    }, error = function(e) {
      showNotification(
        paste("❌ Erro ao exportar resultados:", e$message),
        type = "error",
        duration = 5
      )
    })
  })
  
  cat("✅ Analytics server logic initialized successfully\n")
}

cat("✅ Analytics Server Module loaded successfully\n")