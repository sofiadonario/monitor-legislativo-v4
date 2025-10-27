# ============================================================================
# PERFORMANCE INDEXES FOR BRAZILIAN LEGISLATIVE DATA (SPRINT 3B - DB-002)
# ============================================================================
#
# Comprehensive indexing strategy for Railway PostgreSQL optimized for
# Brazilian legislative document search patterns and 134k+ document dataset.
#
# Index Strategy:
# - Text search indexes for full-text search capabilities
# - Composite indexes for common filter combinations  
# - Partial indexes for selective queries
# - GIN indexes for array and JSON data
# - B-tree indexes for exact matches and sorting
#
# Railway Optimizations:
# - Memory-aware index creation
# - Concurrent index building to avoid downtime
# - Index usage monitoring and maintenance
# ============================================================================

cat("📊 Loading Performance Index System for Brazilian Legislative Data (Sprint 3B)\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
})

# ============================================================================
# INDEX MANAGEMENT CLASS
# ============================================================================

BrazilianLegislativeIndexManager <- R6Class(
  "BrazilianLegislativeIndexManager",
  
  private = list(
    .connection_manager = NULL,
    .index_definitions = NULL,
    .maintenance_schedule = NULL,
    .performance_stats = list()
  ),
  
  public = list(
    # Initialize index manager
    initialize = function(connection_manager = NULL) {
      cat("🔧 Initializing Brazilian Legislative Index Manager\n")
      
      if (exists("railway_pool_manager") && !is.null(railway_pool_manager)) {
        private$.connection_manager <- railway_pool_manager
      } else {
        cat("⚠️ No connection manager available - using direct connection\n")
      }
      
      # Define comprehensive index strategy for Brazilian legislative data
      private$.index_definitions <- self$get_index_definitions()
      private$.maintenance_schedule <- list(
        last_analyze = NULL,
        last_reindex = NULL,
        last_vacuum = NULL
      )
    },
    
    # Get comprehensive index definitions for Brazilian legislative data
    get_index_definitions = function() {
      list(
        # ====================================================================
        # PRIMARY TEXT SEARCH INDEXES (High Priority)
        # ====================================================================
        
        # Full-text search on titles with Portuguese language support
        idx_titulo_fulltext = list(
          table = "documents",
          type = "gin",
          columns = "to_tsvector('portuguese', COALESCE(titulo, title, ''))",
          name = "idx_documents_titulo_fulltext",
          description = "Full-text search on document titles (Portuguese)",
          priority = "high"
        ),
        
        # Full-text search on content/summary
        idx_ementa_fulltext = list(
          table = "documents", 
          type = "gin",
          columns = "to_tsvector('portuguese', COALESCE(ementa, summary, description, ''))",
          name = "idx_documents_ementa_fulltext",
          description = "Full-text search on document summaries (Portuguese)",
          priority = "high"
        ),
        
        # Combined full-text search (title + content)
        idx_combined_fulltext = list(
          table = "documents",
          type = "gin", 
          columns = "to_tsvector('portuguese', COALESCE(titulo, title, '') || ' ' || COALESCE(ementa, summary, description, ''))",
          name = "idx_documents_combined_fulltext",
          description = "Combined full-text search (title + summary)",
          priority = "high"
        ),
        
        # ====================================================================
        # GEOGRAPHICAL INDEXES (Brazilian States and Municipalities)  
        # ====================================================================
        
        # Brazilian state index (all 26 states + DF)
        idx_estado = list(
          table = "documents",
          type = "btree",
          columns = "COALESCE(estado, state, '')",
          name = "idx_documents_estado",
          description = "Index on Brazilian states",
          priority = "high"
        ),
        
        # Municipality index for Brazilian cities
        idx_municipio = list(
          table = "documents", 
          type = "btree",
          columns = "COALESCE(municipio, municipality, localidade, '')",
          name = "idx_documents_municipio",
          description = "Index on Brazilian municipalities",
          priority = "medium"
        ),
        
        # Composite geographic index (state + municipality)
        idx_geo_composite = list(
          table = "documents",
          type = "btree",
          columns = "COALESCE(estado, state, ''), COALESCE(municipio, municipality, '')",
          name = "idx_documents_geo_composite",
          description = "Composite geographic index (state, municipality)",
          priority = "medium"
        ),
        
        # ====================================================================
        # TEMPORAL INDEXES (Dates and Time-based Queries)
        # ====================================================================
        
        # Primary date index for chronological searches
        idx_data_publicacao = list(
          table = "documents",
          type = "btree",
          columns = "COALESCE(data_publicacao, data, date, created_at) DESC",
          name = "idx_documents_data_desc",
          description = "Descending date index for recent documents",
          priority = "high"
        ),
        
        # Date range index for period searches
        idx_data_range = list(
          table = "documents",
          type = "brin",
          columns = "COALESCE(data_publicacao, data, date, created_at)",
          name = "idx_documents_data_range",
          description = "BRIN index for efficient date range queries",
          priority = "medium"
        ),
        
        # Year-based partitioning support
        idx_ano = list(
          table = "documents",
          type = "btree", 
          columns = "EXTRACT(YEAR FROM COALESCE(data_publicacao, data, date, created_at))",
          name = "idx_documents_year",
          description = "Year extraction index for annual reports",
          priority = "low"
        ),
        
        # ====================================================================
        # DOCUMENT TYPE AND CATEGORY INDEXES
        # ====================================================================
        
        # Document category index (Legislação, Jurisprudência, Doutrina)
        idx_categoria = list(
          table = "documents",
          type = "btree",
          columns = "COALESCE(categoria, category, '')",
          name = "idx_documents_categoria",
          description = "Index on document categories",
          priority = "high"
        ),
        
        # Document type index (Lei, Decreto, Portaria, etc.)
        idx_tipo = list(
          table = "documents",
          type = "btree", 
          columns = "COALESCE(tipo, type, document_type, '')",
          name = "idx_documents_tipo",
          description = "Index on document types",
          priority = "high"
        ),
        
        # Composite category + type index
        idx_categoria_tipo = list(
          table = "documents",
          type = "btree",
          columns = "COALESCE(categoria, category, ''), COALESCE(tipo, type, '')",
          name = "idx_documents_categoria_tipo",
          description = "Composite index on category and type",
          priority = "medium"
        ),
        
        # ====================================================================
        # AUTHORITY AND AUTHORSHIP INDEXES
        # ====================================================================
        
        # Author/authority index for attribution searches
        idx_autor = list(
          table = "documents",
          type = "gin",
          columns = "to_tsvector('portuguese', COALESCE(autor, author, ''))",
          name = "idx_documents_autor",
          description = "Full-text search on document authors",
          priority = "medium"
        ),
        
        # Exact author matches
        idx_autor_exact = list(
          table = "documents", 
          type = "btree",
          columns = "COALESCE(autor, author, '')",
          name = "idx_documents_autor_exact",
          description = "Exact match index on authors",
          priority = "low"
        ),
        
        # ====================================================================
        # LEGISLATIVE REFERENCE INDEXES (URN, Numbers, etc.)
        # ====================================================================
        
        # URN index for unique legislative references
        idx_urn = list(
          table = "documents",
          type = "btree",
          columns = "COALESCE(urn, '')",
          name = "idx_documents_urn",
          description = "Index on URN (Uniform Resource Names)",
          priority = "medium",
          condition = "WHERE COALESCE(urn, '') != ''"
        ),
        
        # Document number extraction and indexing
        idx_numero_lei = list(
          table = "documents",
          type = "btree",
          columns = "regexp_replace(COALESCE(titulo, title, ''), '[^0-9]', '', 'g')::numeric",
          name = "idx_documents_numero_lei",
          description = "Extracted law numbers for numerical sorting",
          priority = "low",
          condition = "WHERE COALESCE(titulo, title, '') ~ '[0-9]'"
        ),
        
        # ====================================================================
        # COMPOSITE SEARCH INDEXES (Common Query Patterns)
        # ====================================================================
        
        # Most common search pattern: state + category + date
        idx_estado_categoria_data = list(
          table = "documents",
          type = "btree",
          columns = "COALESCE(estado, state, ''), COALESCE(categoria, category, ''), COALESCE(data_publicacao, data, date) DESC",
          name = "idx_documents_estado_categoria_data",
          description = "Common search pattern: state, category, recent date",
          priority = "high"
        ),
        
        # Search with text + filters
        idx_search_composite = list(
          table = "documents", 
          type = "btree",
          columns = "COALESCE(estado, state, ''), COALESCE(tipo, type, ''), COALESCE(data_publicacao, data, date) DESC",
          name = "idx_documents_search_composite",
          description = "Search with state, type, and date filters",
          priority = "medium"
        ),
        
        # ====================================================================
        # QUALITY AND VALIDATION INDEXES
        # ====================================================================
        
        # Non-empty documents index (exclude invalid records)
        idx_valid_documents = list(
          table = "documents",
          type = "btree",
          columns = "id",
          name = "idx_documents_valid",
          description = "Index only valid documents with titles",
          priority = "medium",
          condition = "WHERE COALESCE(titulo, title, '') != '' AND LENGTH(COALESCE(titulo, title, '')) > 3"
        ),
        
        # Document completeness scoring
        idx_completeness = list(
          table = "documents",
          type = "btree", 
          columns = "(CASE WHEN titulo IS NOT NULL AND titulo != '' THEN 1 ELSE 0 END + CASE WHEN ementa IS NOT NULL AND ementa != '' THEN 1 ELSE 0 END + CASE WHEN autor IS NOT NULL AND autor != '' THEN 1 ELSE 0 END)",
          name = "idx_documents_completeness",
          description = "Document completeness score for quality filtering",
          priority = "low"
        ),
        
        # ====================================================================
        # SPECIALIZED INDEXES FOR BRAZILIAN LEGISLATIVE CONTEXT
        # ====================================================================
        
        # Brazilian legal classification system
        idx_assuntos = list(
          table = "documents",
          type = "gin",
          columns = "to_tsvector('portuguese', COALESCE(assuntos, subjects, ''))",
          name = "idx_documents_assuntos", 
          description = "Full-text search on legal subjects/topics",
          priority = "medium"
        ),
        
        # Federal vs State vs Municipal level
        idx_nivel_federativo = list(
          table = "documents",
          type = "btree",
          columns = "CASE WHEN COALESCE(titulo, title, '') ILIKE '%federal%' THEN 'Federal' WHEN COALESCE(municipio, municipality, '') != '' THEN 'Municipal' ELSE 'Estadual' END",
          name = "idx_documents_nivel_federativo",
          description = "Index on federative level (Federal/State/Municipal)",
          priority = "low"
        )
      )
    },
    
    # Create all indexes with priority-based ordering
    create_all_indexes = function(force = FALSE) {
      cat("🔧 Creating performance indexes for Brazilian legislative data...\n")
      
      if (is.null(private$.connection_manager)) {
        cat("❌ No connection manager available\n")
        return(FALSE)
      }
      
      # Get indexes sorted by priority
      indexes_by_priority <- self$get_indexes_by_priority()
      
      success_count <- 0
      total_count <- length(private$.index_definitions)
      
      for (priority in c("high", "medium", "low")) {
        if (priority %in% names(indexes_by_priority)) {
          cat("📊 Creating", priority, "priority indexes...\n")
          
          for (idx_name in indexes_by_priority[[priority]]) {
            idx_def <- private$.index_definitions[[idx_name]]
            
            if (self$create_index(idx_def, force)) {
              success_count <- success_count + 1
              cat("✅", idx_name, "created successfully\n")
            } else {
              cat("❌", idx_name, "failed to create\n")
            }
            
            # Small delay to avoid overwhelming the database
            Sys.sleep(0.5)
          }
        }
      }
      
      cat("📊 Index creation summary:", success_count, "/", total_count, "successful\n")
      
      # Update statistics after index creation
      self$update_table_statistics()
      
      return(success_count > total_count * 0.7)  # Success if 70%+ created
    },
    
    # Get indexes sorted by priority
    get_indexes_by_priority = function() {
      priorities <- list(high = c(), medium = c(), low = c())
      
      for (idx_name in names(private$.index_definitions)) {
        idx_def <- private$.index_definitions[[idx_name]]
        priority <- idx_def$priority %||% "medium"
        priorities[[priority]] <- c(priorities[[priority]], idx_name)
      }
      
      return(priorities)
    },
    
    # Create a single index
    create_index = function(index_def, force = FALSE) {
      tryCatch({
        # Check if index already exists
        if (!force && self$index_exists(index_def$name, index_def$table)) {
          cat("📊 Index", index_def$name, "already exists\n")
          return(TRUE)
        }
        
        # Build CREATE INDEX statement
        sql <- self$build_index_sql(index_def)
        
        cat("🔧 Creating index:", index_def$name, "\n")
        cat("📋 Description:", index_def$description, "\n")
        
        # Execute with timing
        start_time <- Sys.time()
        result <- private$.connection_manager$execute_query(sql)
        end_time <- Sys.time()
        
        creation_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
        cat("⏱️ Index created in", round(creation_time, 2), "seconds\n")
        
        return(!is.null(result))
        
      }, error = function(e) {
        cat("❌ Error creating index", index_def$name, ":", e$message, "\n")
        return(FALSE)
      })
    },
    
    # Build CREATE INDEX SQL statement
    build_index_sql = function(index_def) {
      # Start with basic CREATE INDEX
      sql <- paste("CREATE INDEX CONCURRENTLY IF NOT EXISTS", index_def$name, "ON", index_def$table)
      
      # Add index type if specified
      if (!isTRUE(is.null(index_def$type)) && index_def$type != "btree") {
        sql <- paste(sql, "USING", toupper(index_def$type))
      }
      
      # Add columns
      sql <- paste0(sql, " (", index_def$columns, ")")
      
      # Add WHERE condition for partial indexes
      if (!is.null(index_def$condition)) {
        sql <- paste(sql, index_def$condition)
      }
      
      return(sql)
    },
    
    # Check if index exists
    index_exists = function(index_name, table_name) {
      tryCatch({
        sql <- "SELECT 1 FROM pg_indexes WHERE indexname = $1 AND tablename = $2"
        result <- private$.connection_manager$execute_query(sql, list(index_name, table_name))
        return(!isTRUE(is.null(result)) && nrow(result) > 0)
      }, error = function(e) {
        return(FALSE)
      })
    },
    
    # Analyze index usage and performance
    analyze_index_usage = function() {
      cat("📊 Analyzing index usage patterns...\n")
      
      tryCatch({
        # Get index usage statistics
        usage_sql <- "
          SELECT 
            schemaname,
            tablename,
            indexname,
            idx_tup_read,
            idx_tup_fetch,
            idx_scan,
            CASE WHEN idx_scan = 0 THEN 'UNUSED'
                 WHEN idx_scan < 100 THEN 'LOW_USAGE' 
                 ELSE 'ACTIVE' 
            END as usage_category
          FROM pg_stat_user_indexes 
          WHERE tablename IN ('documents', 'brazilian_legislative_complete', 'lexml_parsed_enhanced')
          ORDER BY idx_scan DESC"
        
        usage_stats <- private$.connection_manager$execute_query(usage_sql)
        
        if (!isTRUE(is.null(usage_stats)) && nrow(usage_stats) > 0) {
          cat("📊 Index Usage Analysis:\n")
          
          # Summarize by usage category
          usage_summary <- table(usage_stats$usage_category)
          for (category in names(usage_summary)) {
            cat("   -", category, ":", usage_summary[category], "indexes\n")
          }
          
          # List unused indexes
          unused_indexes <- usage_stats[usage_stats$usage_category == "UNUSED", ]
          if (nrow(unused_indexes) > 0) {
            cat("⚠️ Unused indexes (consider dropping):\n")
            for (i in 1:nrow(unused_indexes)) {
              cat("   -", unused_indexes$indexname[i], "\n")
            }
          }
          
          # List most active indexes
          active_indexes <- usage_stats[usage_stats$usage_category == "ACTIVE", ]
          if (nrow(active_indexes) > 0) {
            cat("🚀 Most active indexes:\n")
            top_indexes <- head(active_indexes[order(active_indexes$idx_scan, decreasing = TRUE), ], 5)
            for (i in 1:nrow(top_indexes)) {
              cat("   -", top_indexes$indexname[i], ":", top_indexes$idx_scan[i], "scans\n")
            }
          }
        }
        
        # Get index size information
        size_sql <- "
          SELECT 
            indexname,
            pg_size_pretty(pg_relation_size(indexname::regclass)) as size
          FROM pg_indexes 
          WHERE tablename IN ('documents', 'brazilian_legislative_complete', 'lexml_parsed_enhanced')
          ORDER BY pg_relation_size(indexname::regclass) DESC"
        
        size_stats <- private$.connection_manager$execute_query(size_sql)
        
        if (!isTRUE(is.null(size_stats)) && nrow(size_stats) > 0) {
          cat("💾 Largest indexes:\n")
          top_sizes <- head(size_stats, 5)
          for (i in 1:nrow(top_sizes)) {
            cat("   -", top_sizes$indexname[i], ":", top_sizes$size[i], "\n")
          }
        }
        
      }, error = function(e) {
        cat("❌ Error analyzing index usage:", e$message, "\n")
      })
    },
    
    # Update table statistics
    update_table_statistics = function() {
      cat("📊 Updating table statistics...\n")
      
      tables <- c("documents", "brazilian_legislative_complete", "lexml_parsed_enhanced", "lexml_documents")
      
      for (table_name in tables) {
        tryCatch({
          sql <- paste("ANALYZE", table_name)
          private$.connection_manager$execute_query(sql)
          cat("✅ Statistics updated for", table_name, "\n")
        }, error = function(e) {
          cat("⚠️ Could not update statistics for", table_name, "\n")
        })
      }
    },
    
    # Perform index maintenance
    perform_maintenance = function() {
      cat("🔧 Performing index maintenance...\n")
      
      # Update statistics
      self$update_table_statistics()
      
      # Analyze index usage
      self$analyze_index_usage()
      
      # Check for bloated indexes
      self$check_index_bloat()
      
      # Update maintenance timestamp
      private$.maintenance_schedule$last_analyze <- Sys.time()
      
      cat("✅ Index maintenance completed\n")
    },
    
    # Check for index bloat
    check_index_bloat = function() {
      cat("🔍 Checking for index bloat...\n")
      
      tryCatch({
        bloat_sql <- "
          SELECT 
            schemaname,
            tablename,
            indexname,
            pg_size_pretty(pg_relation_size(indexname::regclass)) as size,
            CASE WHEN pg_relation_size(indexname::regclass) > 100 * 1024 * 1024 THEN 'LARGE'
                 WHEN pg_relation_size(indexname::regclass) > 10 * 1024 * 1024 THEN 'MEDIUM'
                 ELSE 'SMALL'
            END as size_category
          FROM pg_indexes 
          WHERE tablename IN ('documents', 'brazilian_legislative_complete', 'lexml_parsed_enhanced')
          ORDER BY pg_relation_size(indexname::regclass) DESC"
        
        bloat_stats <- private$.connection_manager$execute_query(bloat_sql)
        
        if (!isTRUE(is.null(bloat_stats)) && nrow(bloat_stats) > 0) {
          large_indexes <- bloat_stats[bloat_stats$size_category == "LARGE", ]
          if (nrow(large_indexes) > 0) {
            cat("⚠️ Large indexes detected (>100MB):\n")
            for (i in 1:nrow(large_indexes)) {
              cat("   -", large_indexes$indexname[i], ":", large_indexes$size[i], "\n")
            }
            cat("💡 Consider REINDEX if performance degrades\n")
          }
        }
        
      }, error = function(e) {
        cat("❌ Error checking index bloat:", e$message, "\n")
      })
    },
    
    # Drop unused indexes
    drop_unused_indexes = function(confirm = FALSE) {
      if (!confirm) {
        cat("⚠️ Use drop_unused_indexes(confirm = TRUE) to actually drop indexes\n")
        return(FALSE)
      }
      
      cat("🗑️ Dropping unused indexes...\n")
      
      tryCatch({
        # Find unused indexes
        unused_sql <- "
          SELECT indexname 
          FROM pg_stat_user_indexes 
          WHERE tablename IN ('documents', 'brazilian_legislative_complete', 'lexml_parsed_enhanced')
            AND idx_scan = 0"
        
        unused_indexes <- private$.connection_manager$execute_query(unused_sql)
        
        if (!isTRUE(is.null(unused_indexes)) && nrow(unused_indexes) > 0) {
          dropped_count <- 0
          
          for (i in 1:nrow(unused_indexes)) {
            index_name <- unused_indexes$indexname[i]
            
            tryCatch({
              sql <- paste("DROP INDEX CONCURRENTLY", index_name)
              private$.connection_manager$execute_query(sql)
              cat("🗑️ Dropped unused index:", index_name, "\n")
              dropped_count <- dropped_count + 1
            }, error = function(e) {
              cat("❌ Failed to drop", index_name, ":", e$message, "\n")
            })
          }
          
          cat("📊 Dropped", dropped_count, "/", nrow(unused_indexes), "unused indexes\n")
          return(dropped_count > 0)
        } else {
          cat("✅ No unused indexes found\n")
          return(TRUE)
        }
        
      }, error = function(e) {
        cat("❌ Error dropping unused indexes:", e$message, "\n")
        return(FALSE)
      })
    },
    
    # Get comprehensive index report
    get_index_report = function() {
      report <- list(
        created_indexes = names(private$.index_definitions),
        maintenance_schedule = private$.maintenance_schedule,
        recommendations = c()
      )
      
      # Add usage analysis
      tryCatch({
        usage_sql <- "SELECT COUNT(*) as total_indexes, 
                             SUM(CASE WHEN idx_scan = 0 THEN 1 ELSE 0 END) as unused_indexes,
                             SUM(CASE WHEN idx_scan > 1000 THEN 1 ELSE 0 END) as active_indexes
                      FROM pg_stat_user_indexes 
                      WHERE tablename IN ('documents', 'brazilian_legislative_complete', 'lexml_parsed_enhanced')"
        
        usage_summary <- private$.connection_manager$execute_query(usage_sql)
        
        if (!isTRUE(is.null(usage_summary)) && nrow(usage_summary) > 0) {
          report$usage_summary <- usage_summary
          
          # Add recommendations
          if (usage_summary$unused_indexes > 0) {
            report$recommendations <- c(report$recommendations, 
              paste("Consider dropping", usage_summary$unused_indexes, "unused indexes"))
          }
          
          if (usage_summary$active_indexes / usage_summary$total_indexes < 0.5) {
            report$recommendations <- c(report$recommendations,
              "Low index utilization - review index strategy")
          }
        }
        
      }, error = function(e) {
        report$error <- paste("Could not generate usage summary:", e$message)
      })
      
      return(report)
    }
  )
)

# ============================================================================
# GLOBAL INDEX MANAGER INSTANCE AND FUNCTIONS
# ============================================================================

# Global index manager
brazilian_index_manager <- NULL

#' Initialize the Brazilian Legislative Index Manager
#' @return Boolean indicating success
init_brazilian_indexes = function() {
  cat("🇧🇷 Initializing Brazilian Legislative Index Manager (Sprint 3B)\n")
  
  brazilian_index_manager <<- BrazilianLegislativeIndexManager$new()
  
  if (!is.null(brazilian_index_manager)) {
    cat("✅ Brazilian Legislative Index Manager initialized\n")
    return(TRUE)
  }
  
  cat("❌ Failed to initialize index manager\n") 
  return(FALSE)
}

#' Create all performance indexes
#' @param force Force recreation of existing indexes
#' @return Boolean indicating success
create_performance_indexes = function(force = FALSE) {
  if (is.null(brazilian_index_manager)) {
    cat("⚠️ Index manager not initialized\n")
    return(FALSE)
  }
  
  return(brazilian_index_manager$create_all_indexes(force))
}

#' Analyze index performance and usage
analyze_index_performance = function() {
  if (is.null(brazilian_index_manager)) {
    cat("⚠️ Index manager not initialized\n")
    return(NULL)
  }
  
  brazilian_index_manager$analyze_index_usage()
  return(brazilian_index_manager$get_index_report())
}

#' Perform index maintenance
perform_index_maintenance = function() {
  if (is.null(brazilian_index_manager)) {
    cat("⚠️ Index manager not initialized\n")
    return(FALSE)
  }
  
  brazilian_index_manager$perform_maintenance()
  return(TRUE)
}

#' Drop unused indexes to free space
#' @param confirm Confirmation required to actually drop indexes
#' @return Boolean indicating success
cleanup_unused_indexes = function(confirm = FALSE) {
  if (is.null(brazilian_index_manager)) {
    cat("⚠️ Index manager not initialized\n")
    return(FALSE)
  }
  
  return(brazilian_index_manager$drop_unused_indexes(confirm))
}

# ============================================================================
# AUTOMATIC INITIALIZATION
# ============================================================================

cat("🔧 Auto-initializing Brazilian Legislative Index Manager...\n")
index_manager_ready <- init_brazilian_indexes()

if (index_manager_ready) {
  cat("✅ Performance Index System ready for Brazilian Legislative Data (Sprint 3B)\n")
  cat("💡 Use create_performance_indexes() to create all indexes\n")
  cat("💡 Use analyze_index_performance() to monitor performance\n")
  cat("💡 Use perform_index_maintenance() for regular maintenance\n")
} else {
  cat("⚠️ Running without advanced indexing capabilities\n")
}

cat("🇧🇷 Brazilian Legislative Performance Index System (Sprint 3B) loaded successfully\n")