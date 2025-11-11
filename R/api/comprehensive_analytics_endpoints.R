# Comprehensive Analytics API Endpoints
# Monitor Legislativo v4 - All Analytics in One File
# ====================================================

# Load analytics modules
if (file.exists("R/analytics/geographic_analytics.R")) {
  source("R/analytics/geographic_analytics.R", local = TRUE)
}
if (file.exists("R/analytics/temporal_analytics.R")) {
  source("R/analytics/temporal_analytics.R", local = TRUE)
}
if (file.exists("R/analytics/content_analytics.R")) {
  source("R/analytics/content_analytics.R", local = TRUE)
}

#' ==============================================================================
#' GEOGRAPHIC ANALYTICS ENDPOINTS
#' ==============================================================================

#' @get /api/v1/analytics/geographic/state-rankings
#' @param metric:character Metric to rank by (total_docs, recent_activity, productivity, diversity)
#' @param limit:integer Number of states to return (default 27)
#' @response 200 JSON array of state rankings
#' @response 500 Error message
function(req, res, metric = "total_docs", limit = 27) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- calculate_state_rankings(db_conn, metric, as.integer(limit))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to calculate state rankings"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/geographic/compare-states
#' @param state1:character First state code
#' @param state2:character Second state code
#' @response 200 JSON comparison data
#' @response 400 Missing parameters
#' @response 500 Error message
function(req, res, state1 = NULL, state2 = NULL) {
  if (is.null(state1) || is.null(state2)) {
    res$status <- 400
    return(list(error = "Parameters state1 and state2 are required"))
  }

  tryCatch({
    db_conn <- get_db_connection()
    result <- compare_states(db_conn, state1, state2)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to compare states"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/geographic/regional-statistics
#' @response 200 JSON array of regional statistics
#' @response 500 Error message
function(req, res) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- calculate_regional_statistics(db_conn)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to calculate regional statistics"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/geographic/hotspots
#' @param threshold:integer Minimum documents for hotspot (default 100)
#' @response 200 JSON array of geographic hotspots
#' @response 500 Error message
function(req, res, threshold = 100) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- calculate_geographic_hotspots(db_conn, as.integer(threshold))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to calculate hotspots"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/geographic/state-patterns
#' @param state:character State code to analyze
#' @param years:integer Years to look back (default 10)
#' @response 200 JSON state pattern data
#' @response 400 Missing state parameter
#' @response 500 Error message
function(req, res, state = NULL, years = 10) {
  if (is.null(state)) {
    res$status <- 400
    return(list(error = "Parameter 'state' is required"))
  }

  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_state_patterns(db_conn, state, as.integer(years))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze state patterns"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/geographic/state-similarity
#' @param state:character Reference state code
#' @param top:integer Number of similar states to return (default 10)
#' @response 200 JSON similarity scores
#' @response 400 Missing state parameter
#' @response 500 Error message
function(req, res, state = NULL, top = 10) {
  if (is.null(state)) {
    res$status <- 400
    return(list(error = "Parameter 'state' is required"))
  }

  tryCatch({
    db_conn <- get_db_connection()
    result <- calculate_state_similarity(db_conn, state, as.integer(top))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to calculate similarity"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' ==============================================================================
#' TEMPORAL ANALYTICS ENDPOINTS
#' ==============================================================================

#' @get /api/v1/analytics/temporal/decade-trends
#' @response 200 JSON array of decade statistics
#' @response 500 Error message
function(req, res) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- calculate_decade_trends(db_conn)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to calculate decade trends"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/temporal/seasonal-patterns
#' @param years:integer Years to analyze (default 5)
#' @response 200 JSON seasonal pattern data
#' @response 500 Error message
function(req, res, years = 5) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_seasonal_patterns(db_conn, as.integer(years))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze seasonal patterns"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/temporal/milestones
#' @response 200 JSON array of legislative milestones
#' @response 500 Error message
function(req, res) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- detect_legislative_milestones(db_conn)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to detect milestones"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/temporal/cycles
#' @param state:character Optional state filter
#' @response 200 JSON legislative cycle analysis
#' @response 500 Error message
function(req, res, state = NULL) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_legislative_cycles(db_conn, state)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze cycles"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/temporal/forecast
#' @param years:integer Years ahead to forecast (default 3)
#' @response 200 JSON forecast data
#' @response 500 Error message
function(req, res, years = 3) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- calculate_legislative_forecast(db_conn, as.integer(years))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to calculate forecast"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/temporal/velocity
#' @param window:integer Rolling window size (default 3)
#' @response 200 JSON velocity metrics
#' @response 500 Error message
function(req, res, window = 3) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_legislative_velocity(db_conn, as.integer(window))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze velocity"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' ==============================================================================
#' CONTENT ANALYTICS ENDPOINTS
#' ==============================================================================

#' @get /api/v1/analytics/content/type-evolution
#' @param years:integer Years to analyze (default 20)
#' @response 200 JSON document type evolution data
#' @response 500 Error message
function(req, res, years = 20) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_document_type_evolution(db_conn, as.integer(years))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze type evolution"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/content/authority-distribution
#' @response 200 JSON authority level distribution
#' @response 500 Error message
function(req, res) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_authority_distribution(db_conn)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze authority distribution"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/content/transport-theme
#' @response 200 JSON transport legislation analysis
#' @response 500 Error message
function(req, res) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_transport_theme(db_conn)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze transport theme"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/content/common-terms
#' @param limit:integer Number of terms to return (default 50)
#' @response 200 JSON array of common legal terms
#' @response 500 Error message
function(req, res, limit = 50) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_common_legal_terms(db_conn, as.integer(limit))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze legal terms"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/content/document-length
#' @response 200 JSON document length statistics
#' @response 500 Error message
function(req, res) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- analyze_document_length(db_conn)

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to analyze document length"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' @get /api/v1/analytics/content/emerging-topics
#' @param recent:integer Recent years to consider (default 3)
#' @param compare:integer Comparison period years (default 10)
#' @response 200 JSON emerging topics data
#' @response 500 Error message
function(req, res, recent = 3, compare = 10) {
  tryCatch({
    db_conn <- get_db_connection()
    result <- detect_emerging_topics(db_conn, as.integer(recent), as.integer(compare))

    if (is.null(result)) {
      res$status <- 500
      return(list(error = "Failed to detect emerging topics"))
    }

    return(result)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Error:", e$message)))
  })
}


#' ==============================================================================
#' COMBINED ANALYTICS DASHBOARD ENDPOINT
#' ==============================================================================

#' @get /api/v1/analytics/dashboard/comprehensive
#' @response 200 JSON comprehensive dashboard data
#' @response 500 Error message
function(req, res) {
  tryCatch({
    db_conn <- get_db_connection()

    dashboard <- list(
      geographic = list(
        state_rankings = calculate_state_rankings(db_conn, "total_docs", 10),
        regional_statistics = calculate_regional_statistics(db_conn),
        hotspots = calculate_geographic_hotspots(db_conn, 100)
      ),
      temporal = list(
        decade_trends = calculate_decade_trends(db_conn),
        recent_milestones = detect_legislative_milestones(db_conn),
        velocity = analyze_legislative_velocity(db_conn, 3)
      ),
      content = list(
        authority_distribution = analyze_authority_distribution(db_conn),
        transport_theme = analyze_transport_theme(db_conn),
        emerging_topics = detect_emerging_topics(db_conn, 3, 10)
      ),
      metadata = list(
        generated_at = Sys.time(),
        version = "v4.0",
        analytics_modules = c("geographic", "temporal", "content")
      )
    )

    return(dashboard)

  }, error = function(e) {
    res$status <- 500
    return(list(error = paste("Dashboard generation error:", e$message)))
  })
}


#' Helper function to get database connection
#' @return Database connection or NULL
get_db_connection <- function() {
  tryCatch({
    # Try to get connection from parent environment
    if (exists("db_pool", envir = parent.frame(2))) {
      return(get("db_pool", envir = parent.frame(2)))
    }

    # Try global connection
    if (exists("db_connection", envir = .GlobalEnv)) {
      return(get("db_connection", envir = .GlobalEnv))
    }

    # Create new connection if needed
    if (requireNamespace("DBI", quietly = TRUE) && requireNamespace("RPostgres", quietly = TRUE)) {
      conn <- DBI::dbConnect(
        RPostgres::Postgres(),
        host = Sys.getenv("PGHOST", "localhost"),
        port = as.integer(Sys.getenv("PGPORT", "5432")),
        dbname = Sys.getenv("PGDATABASE", "monitor_legislativo"),
        user = Sys.getenv("PGUSER", "postgres"),
        password = Sys.getenv("PGPASSWORD", "")
      )
      return(conn)
    }

    return(NULL)

  }, error = function(e) {
    message("Database connection error: ", e$message)
    return(NULL)
  })
}
