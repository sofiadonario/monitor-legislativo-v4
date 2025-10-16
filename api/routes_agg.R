# ============================================================================
# AGGREGATION API ROUTES
# ============================================================================
# Dashboard statistics using materialized views

library(glue)

#' @get /api/v1/agg/counts
#' @serializer json
#' @tag Aggregations
#' @description Get document counts grouped by year, jurisdiction, or state
#' @param group_by:[year|jurisdiction|state] Group by field (required)
#' @param date_from:character Start date YYYY-MM-DD (optional)
#' @param date_to:character End date YYYY-MM-DD (optional)
pr$get("/api/v1/agg/counts", with_http_cache(function(req, res) {
  group_by  <- as_enum(req$args$group_by %||% "year", "group_by", c("year", "jurisdiction", "state"))
  date_from <- safe_date(req$args$date_from, "date_from")
  date_to   <- safe_date(req$args$date_to, "date_to")

  tbl <- switch(group_by,
    "year"         = "mv_docs_year_juris",
    "jurisdiction" = "mv_docs_year_juris",
    "state"        = "mv_docs_state_year"
  )

  where <- c()
  if (!is.na(date_from)) where <- c(where, "year >= extract(year from $1::date)")
  if (!is.na(date_to))   where <- c(where, "year <= extract(year from $2::date)")

  sql <- glue("
    SELECT {group_by} AS key, SUM(n_docs) AS count
    FROM {tbl}
    {if (length(where) > 0) paste('WHERE', paste(where, collapse = ' AND ')) else ''}
    GROUP BY {group_by}
    ORDER BY {group_by};
  ")

  params <- Filter(Negate(is.na), list(date_from, date_to))
  data <- dbGetQuery(con_pg, sql, params = params)

  if (nrow(data) == 0) {
    return(list(buckets = list()))
  }

  list(
    buckets = lapply(seq_len(nrow(data)), function(i) {
      list(key = data$key[i], count = data$count[i])
    })
  )
}, ttl = 120))
