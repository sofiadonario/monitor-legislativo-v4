# ============================================================================
# DOCUMENT API ROUTES
# ============================================================================
# Individual document retrieval endpoints

#' @get /api/v1/legis/<id>
#' @serializer json
#' @tag Documents
#' @description Get a single legislative document by ID
#' @param id:character Document ID (required)
#' @response 200 Document details
#' @response 404 Document not found
pr$get("/api/v1/legis/<id>", with_http_cache(function(req, res, id) {
  id <- as_scalar(id, "id")

  doc <- dbGetQuery(con_pg, "
    SELECT id, title, full_text, summary, jurisdiction, status,
           date AS presented_date, date AS last_movement_date
    FROM legis_docs
    WHERE id = $1
  ", params = list(id))

  if (nrow(doc) == 0) {
    res$status <- 404
    return(list(
      error = "not_found",
      message = "Document not found"
    ))
  }

  list(
    id = doc$id[[1]],
    title = doc$title[[1]],
    full_text = doc$full_text[[1]],
    summary = doc$summary[[1]],
    jurisdiction = doc$jurisdiction[[1]],
    status = doc$status[[1]],
    dates = list(
      presented = as.character(doc$presented_date[[1]]),
      last_movement = as.character(doc$last_movement_date[[1]])
    )
  )
}, ttl = 300))
