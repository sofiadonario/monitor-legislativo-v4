# ============================================================================
# MAP API ROUTES
# ============================================================================
# Geographic data endpoints for Brazilian states and municipalities

source("api/lib/validators.R")
source("api/lib/http_cache.R")

#' @get /map/states
#' @serializer json
#' @tag Geographic
#' @description Get document counts by Brazilian state for map visualization
#' @param year:int Filter by year (optional)
get_states_map_data <- with_http_cache(function(req, res) {
  year <- if (!is.null(req$args$year)) {
    safe_int(req$args$year, "year", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  con <- get("con_pg", envir = .GlobalEnv)

  sql <- if (!is.na(year)) {
    "
    SELECT
      state,
      SUM(n_docs) as total_docs
    FROM mv_docs_state_year
    WHERE year = $1 AND state IS NOT NULL
    GROUP BY state
    ORDER BY total_docs DESC
    "
  } else {
    "
    SELECT
      state,
      SUM(n_docs) as total_docs
    FROM mv_docs_state_year
    WHERE state IS NOT NULL
    GROUP BY state
    ORDER BY total_docs DESC
    "
  }

  params <- if (!is.na(year)) list(year) else list()

  tryCatch(
    {
      results <- dbGetQuery(con, sql, params = params)

      # Add state names for better UX
      state_names <- list(
        AC = "Acre",
        AL = "Alagoas",
        AP = "Amapá",
        AM = "Amazonas",
        BA = "Bahia",
        CE = "Ceará",
        DF = "Distrito Federal",
        ES = "Espírito Santo",
        GO = "Goiás",
        MA = "Maranhão",
        MT = "Mato Grosso",
        MS = "Mato Grosso do Sul",
        MG = "Minas Gerais",
        PA = "Pará",
        PB = "Paraíba",
        PR = "Paraná",
        PE = "Pernambuco",
        PI = "Piauí",
        RJ = "Rio de Janeiro",
        RN = "Rio Grande do Norte",
        RS = "Rio Grande do Sul",
        RO = "Rondônia",
        RR = "Roraima",
        SC = "Santa Catarina",
        SP = "São Paulo",
        SE = "Sergipe",
        TO = "Tocantins"
      )

      # Enrich results with state names
      if (nrow(results) > 0) {
        results$state_name <- sapply(results$state, function(code) {
          state_names[[code]] %||% code
        })
      }

      list(
        filters = list(
          year = if (!is.na(year)) year else NULL
        ),
        count = nrow(results),
        states = results,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to retrieve state map data: %s", e$message)
      )
    }
  )
}, ttl = 1800)

#' @get /map/municipalities/<state>
#' @serializer json
#' @tag Geographic
#' @description Get document counts by municipality for a specific state
#' @param state:character Brazilian state code (required, e.g., SP, RJ)
#' @param year:int Filter by year (optional)
get_municipalities_map_data <- with_http_cache(function(req, res, state) {
  state <- validate_state(state)

  if (state == "all") {
    res$status <- 400
    return(list(
      error = "invalid_request",
      message = "State code is required"
    ))
  }

  year <- if (!is.null(req$args$year)) {
    safe_int(req$args$year, "year", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  con <- get("con_pg", envir = .GlobalEnv)

  sql_base <- "
    SELECT
      municipality,
      COUNT(*) as total_docs
    FROM legis_docs
    WHERE state = $1
      AND municipality IS NOT NULL
      AND municipality != ''
  "

  params <- list(state)
  param_count <- 1

  if (!is.na(year)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year = $%d", param_count))
    params <- c(params, list(year))
  }

  sql_base <- paste(sql_base, "GROUP BY municipality ORDER BY total_docs DESC")

  tryCatch(
    {
      results <- dbGetQuery(con, sql_base, params = params)

      list(
        state = state,
        filters = list(
          year = if (!is.na(year)) year else NULL
        ),
        count = nrow(results),
        municipalities = results,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to retrieve municipality data: %s", e$message)
      )
    }
  )
}, ttl = 1800)

#' @get /map/heatmap
#' @serializer json
#' @tag Geographic
#' @description Get geographic heatmap data for all documents
#' @param year_start:int Start year (optional)
#' @param year_end:int End year (optional)
#' @param jurisdiction:[federal|state|municipal|all] Filter by jurisdiction
get_heatmap_data <- with_http_cache(function(req, res) {
  year_start <- if (!is.null(req$args$year_start)) {
    safe_int(req$args$year_start, "year_start", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  year_end <- if (!is.null(req$args$year_end)) {
    safe_int(req$args$year_end, "year_end", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  jurisdiction <- validate_jurisdiction(req$args$jurisdiction %||% "all")

  con <- get("con_pg", envir = .GlobalEnv)

  # Use materialized view for fast aggregation
  sql_base <- "
    SELECT
      state,
      SUM(n_docs) as total_docs
    FROM mv_docs_state_year
    WHERE state IS NOT NULL
  "

  params <- list()
  param_count <- 0

  if (!is.na(year_start)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year >= $%d", param_count))
    params <- c(params, list(year_start))
  }

  if (!is.na(year_end)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year <= $%d", param_count))
    params <- c(params, list(year_end))
  }

  sql_base <- paste(sql_base, "GROUP BY state ORDER BY total_docs DESC")

  tryCatch(
    {
      results <- dbGetQuery(con, sql_base, params = params)

      # Calculate intensity (normalized 0-1 for heatmap)
      if (nrow(results) > 0 && max(results$total_docs) > 0) {
        results$intensity <- results$total_docs / max(results$total_docs)
      } else {
        results$intensity <- 0
      }

      list(
        filters = list(
          year_start = if (!is.na(year_start)) year_start else NULL,
          year_end = if (!is.na(year_end)) year_end else NULL,
          jurisdiction = jurisdiction
        ),
        count = nrow(results),
        heatmap_data = results,
        meta = list(
          max_docs = if (nrow(results) > 0) max(results$total_docs) else 0,
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to generate heatmap data: %s", e$message)
      )
    }
  )
}, ttl = 1800)

#' @get /map/geojson/states
#' @serializer json
#' @tag Geographic
#' @description Get Brazilian states as GeoJSON with document counts
#' @param year:int Filter by year (optional)
get_states_geojson <- with_http_cache(function(req, res) {
  year <- if (!is.null(req$args$year)) {
    safe_int(req$args$year, "year", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  con <- get("con_pg", envir = .GlobalEnv)

  # Get document counts
  sql <- if (!is.na(year)) {
    "
    SELECT
      state,
      SUM(n_docs) as total_docs
    FROM mv_docs_state_year
    WHERE year = $1 AND state IS NOT NULL
    GROUP BY state
    "
  } else {
    "
    SELECT
      state,
      SUM(n_docs) as total_docs
    FROM mv_docs_state_year
    WHERE state IS NOT NULL
    GROUP BY state
    "
  }

  params <- if (!is.na(year)) list(year) else list()

  tryCatch(
    {
      results <- dbGetQuery(con, sql, params = params)

      # Build GeoJSON structure
      # Note: Full state geometries would come from PostGIS if available
      # For now, provide simplified structure for client-side rendering

      features <- lapply(1:nrow(results), function(i) {
        list(
          type = "Feature",
          properties = list(
            state = results$state[i],
            total_docs = results$total_docs[i]
          ),
          geometry = list(
            type = "Point",
            coordinates = c(0, 0) # Placeholder - use actual coordinates or PostGIS
          )
        )
      })

      geojson <- list(
        type = "FeatureCollection",
        features = features,
        meta = list(
          year = if (!is.na(year)) year else NULL,
          timestamp = Sys.time()
        )
      )

      geojson
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to generate GeoJSON: %s", e$message)
      )
    }
  )
}, ttl = 3600)
