# ============================================================================
# MAP API ROUTES
# ============================================================================
# Geographic data endpoints for choropleth maps

library(glue)

# Choropleth implementation
choropleth_impl <- function(geo, metric, year) {
  tbl <- if (metric == "bills_per_100k") "mv_docs_state_density" else "mv_docs_state_year"
  where <- if (!is.na(year)) glue("WHERE year = {year}") else ""
  sql <- glue("
    SELECT state AS id,
           {if (metric == 'bills_per_100k') 'bills_per_100k' else 'n_docs'} AS value
    FROM {tbl}
    {where};
  ")

  data <- dbGetQuery(con_pg, sql)

  list(
    meta = list(geo = geo, metric = metric, year = year),
    features = lapply(seq_len(nrow(data)), function(i) {
      list(id = data$id[i], value = data$value[i])
    })
  )
}

#' @get /api/v1/map/choropleth
#' @serializer json
#' @tag Maps
#' @description Get geographic choropleth data for Brazilian states
#' @param geo:[estado|municipio] Geographic level (default: estado)
#' @param metric:[bills_per_100k|n_docs] Metric to display (default: n_docs)
#' @param year:int Filter by specific year (optional)
pr$get("/api/v1/map/choropleth", with_http_cache(function(req, res) {
  geo    <- as_enum(req$args$geo %||% "estado", "geo", c("estado", "municipio"))
  metric <- as_enum(req$args$metric %||% "n_docs", "metric", c("bills_per_100k", "n_docs"))
  year   <- if (!is.null(req$args$year)) as.integer(req$args$year) else NA_integer_

  out <- choropleth_impl(geo, metric, year)

  if (length(out$features) == 0) {
    out$features <- list()
  }

  out
}, ttl = 300))
