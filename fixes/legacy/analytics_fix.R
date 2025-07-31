# Simplified analytics function to replace the complex one
get_search_analytics_simple <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_day = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  }
  
  cat("DEBUG: get_search_analytics_simple() called\n")
  
  tryCatch({
    # Total documents
    total <- as.numeric(dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count)
    cat("DEBUG: Total documents found:", total, "\n")
    
    # Documents by year - simple approach
    by_year <- dbGetQuery(db_pool, "
      SELECT 
        EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at::date)) as year,
        COUNT(*) as count
      FROM documents 
      WHERE COALESCE(data_publicacao, created_at::date) IS NOT NULL
      GROUP BY EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at::date))
      ORDER BY year DESC
      LIMIT 10
    ")
    cat("DEBUG: Year query got", nrow(by_year), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_year) > 0) {
      by_year$count <- as.numeric(by_year$count)
      by_year$year <- as.numeric(by_year$year)
      cat("DEBUG: Years data:", paste(by_year$year, collapse = ", "), "\n")
    } else {
      cat("DEBUG: No year data found\n")
    }
    
    # Documents by month - simple approach
    by_month <- dbGetQuery(db_pool, "
      SELECT 
        EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at::date)) as year,
        EXTRACT(MONTH FROM COALESCE(data_publicacao, created_at::date)) as month,
        COUNT(*) as count,
        TO_CHAR(COALESCE(data_publicacao, created_at::date), 'YYYY-MM') as year_month
      FROM documents 
      WHERE COALESCE(data_publicacao, created_at::date) IS NOT NULL
      GROUP BY EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at::date)), 
               EXTRACT(MONTH FROM COALESCE(data_publicacao, created_at::date)),
               TO_CHAR(COALESCE(data_publicacao, created_at::date), 'YYYY-MM')
      ORDER BY year DESC, month DESC
      LIMIT 12
    ")
    cat("DEBUG: Month query got", nrow(by_month), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_month) > 0) {
      by_month$count <- as.numeric(by_month$count)
      by_month$year <- as.numeric(by_month$year)
      by_month$month <- as.numeric(by_month$month)
    }
    
    # Documents by day - simple approach
    by_day <- dbGetQuery(db_pool, "
      SELECT 
        COALESCE(data_publicacao, created_at::date)::date as day,
        COUNT(*) as count,
        TO_CHAR(COALESCE(data_publicacao, created_at::date), 'YYYY-MM-DD') as formatted_date
      FROM documents 
      WHERE COALESCE(data_publicacao, created_at::date) IS NOT NULL
      GROUP BY COALESCE(data_publicacao, created_at::date)::date,
               TO_CHAR(COALESCE(data_publicacao, created_at::date), 'YYYY-MM-DD')
      ORDER BY day DESC
      LIMIT 30
    ")
    cat("DEBUG: Day query got", nrow(by_day), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_day) > 0) {
      by_day$count <- as.numeric(by_day$count)
      by_day$day <- as.Date(by_day$day)
    }
    
    # Documents by state (top 10)
    by_state <- dbGetQuery(db_pool, "
      SELECT 
        estado,
        COUNT(*) as count
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado
      ORDER BY count DESC
      LIMIT 10
    ")
    cat("DEBUG: State query got", nrow(by_state), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_state) > 0) {
      by_state$count <- as.numeric(by_state$count)
    }
    
    # Documents by type
    by_type <- dbGetQuery(db_pool, "
      SELECT 
        tipo,
        COUNT(*) as count
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != ''
      GROUP BY tipo
      ORDER BY count DESC
    ")
    cat("DEBUG: Type query got", nrow(by_type), "rows\n")
    
    # Convert integer64 to numeric
    if (nrow(by_type) > 0) {
      by_type$count <- as.numeric(by_type$count)
    }
    
    # Recent documents - simple approach
    recent <- dbGetQuery(db_pool, "
      SELECT 
        d.titulo,
        d.tipo,
        d.estado,
        COALESCE(d.data_publicacao, d.created_at::date) as enacting_date
      FROM documents d
      WHERE COALESCE(d.data_publicacao, d.created_at::date) IS NOT NULL
        AND d.titulo IS NOT NULL
      ORDER BY COALESCE(d.data_publicacao, d.created_at::date) DESC
      LIMIT 10
    ")
    cat("DEBUG: Recent query got", nrow(recent), "rows\n")
    
    # Date range - simple approach
    date_range <- dbGetQuery(db_pool, "
      SELECT 
        MIN(COALESCE(data_publicacao, created_at::date)) as min_date,
        MAX(COALESCE(data_publicacao, created_at::date)) as max_date
      FROM documents 
      WHERE COALESCE(data_publicacao, created_at::date) IS NOT NULL
    ")
    cat("DEBUG: Date range query completed\n")
    
    result <- list(
      total_documents = total,
      documents_by_year = by_year,
      documents_by_month = by_month,
      documents_by_day = by_day,
      documents_by_state = by_state,
      documents_by_type = by_type,
      recent_documents = recent,
      date_range = list(
        min = date_range$min_date,
        max = date_range$max_date
      )
    )
    
    cat("DEBUG: Analytics completed successfully\n")
    return(result)
    
  }, error = function(e) {
    cat("ERROR in get_search_analytics_simple():", e$message, "\n")
    cat("Stack trace:\n")
    print(e)
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_month = data.frame(),
      documents_by_day = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  })
}