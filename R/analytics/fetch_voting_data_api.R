# ==============================================================================
# BRAZILIAN LEGISLATIVE VOTING DATA API SCRAPER
# ==============================================================================
# Fetches real voting data from Câmara dos Deputados and Senado Federal APIs
# Populates Sprint 4 Predictive Analytics tables
#
# Data Sources:
# - Câmara dos Deputados Open Data API
# - Senado Federal Open Data API
#
# Tables Populated:
# - legislators (with party and state info)
# - bill_events (from proposal tramitação)
# - roll_call_votes (from votações)
#
# Author: Monitor Legislativo v4
# Date: 2025-11-16
# ==============================================================================

library(httr)
library(jsonlite)
library(dplyr)
library(DBI)
library(pool)
library(lubridate)
library(purrr)

#' Fetch Legislators from Câmara dos Deputados API
#'
#' @param legislature_id Integer. Legislature number (e.g., 57 for 2023-2027)
#' @return Data frame with legislator information
#' @export
fetch_camara_legislators <- function(legislature_id = 57) {
  cat(sprintf("\n=== Fetching Legislators from Câmara (Legislature %d) ===\n", legislature_id))

  base_url <- "https://dadosabertos.camara.leg.br/api/v2"
  endpoint <- sprintf("%s/deputados", base_url)

  params <- list(
    idLegislatura = legislature_id,
    ordem = "ASC",
    ordenarPor = "nome",
    itens = 1000
  )

  response <- GET(endpoint, query = params)

  if (status_code(response) != 200) {
    stop(sprintf("API Error: %d - %s", status_code(response), content(response, "text")))
  }

  data <- content(response, "parsed")

  if (length(data$dados) == 0) {
    warning("No legislators found")
    return(data.frame())
  }

  legislators <- map_df(data$dados, function(dep) {
    data.frame(
      id = paste0("dep_", dep$id),
      name = ifelse(is.null(dep$nome), NA_character_, dep$nome),
      party = ifelse(is.null(dep$siglaPartido), NA_character_, dep$siglaPartido),
      state = ifelse(is.null(dep$siglaUf), NA_character_, dep$siglaUf),
      photo_url = ifelse(is.null(dep$urlFoto), NA_character_, dep$urlFoto),
      email = ifelse(is.null(dep$email), NA_character_, dep$email),
      stringsAsFactors = FALSE
    )
  })

  cat(sprintf("✅ Fetched %d legislators from Câmara\n", nrow(legislators)))

  return(legislators)
}

#' Fetch Senators from Senado Federal API
#'
#' @return Data frame with senator information
#' @export
fetch_senado_legislators <- function() {
  cat("\n=== Fetching Senators from Senado ===\n")

  base_url <- "https://legis.senado.leg.br/dadosabertos/senador/lista/atual"

  response <- GET(base_url)

  if (status_code(response) != 200) {
    warning(sprintf("Senado API Error: %d", status_code(response)))
    return(data.frame())
  }

  data <- content(response, "parsed")

  if (is.null(data$ListaParlamentarEmExercicio$Parlamentares$Parlamentar)) {
    warning("No senators found")
    return(data.frame())
  }

  senators <- map_df(data$ListaParlamentarEmExercicio$Parlamentares$Parlamentar, function(sen) {
    data.frame(
      id = paste0("sen_", sen$IdentificacaoParlamentar$CodigoParlamentar),
      name = ifelse(is.null(sen$IdentificacaoParlamentar$NomeParlamentar), NA_character_, sen$IdentificacaoParlamentar$NomeParlamentar),
      party = ifelse(is.null(sen$IdentificacaoParlamentar$SiglaPartidoParlamentar), NA_character_, sen$IdentificacaoParlamentar$SiglaPartidoParlamentar),
      state = ifelse(is.null(sen$IdentificacaoParlamentar$UfParlamentar), NA_character_, sen$IdentificacaoParlamentar$UfParlamentar),
      email = ifelse(is.null(sen$IdentificacaoParlamentar$EmailParlamentar), NA_character_, sen$IdentificacaoParlamentar$EmailParlamentar),
      stringsAsFactors = FALSE
    )
  })

  cat(sprintf("✅ Fetched %d senators from Senado\n", nrow(senators)))

  return(senators)
}

#' Fetch Roll Call Votes for a Specific Proposal
#'
#' @param proposal_id Integer. Câmara proposal ID
#' @return Data frame with roll call votes, or NULL if no votes exist
#' @export
fetch_proposal_votes <- function(proposal_id) {
  base_url <- "https://dadosabertos.camara.leg.br/api/v2"
  endpoint <- sprintf("%s/proposicoes/%d/votacoes", base_url, proposal_id)

  response <- GET(endpoint)

  if (status_code(response) != 200) {
    return(NULL)
  }

  data <- content(response, "parsed")

  if (length(data$dados) == 0) {
    return(NULL)
  }

  all_votes <- list()

  for (votacao in data$dados) {
    vote_id <- votacao$id
    vote_date <- as.Date(votacao$dataHoraRegistro)

    # Fetch detailed vote data
    vote_endpoint <- sprintf("%s/votacoes/%s/votos", base_url, vote_id)
    vote_response <- GET(vote_endpoint)

    if (status_code(vote_response) != 200) next

    vote_data <- content(vote_response, "parsed")

    if (length(vote_data$dados) == 0) next

    votes <- map_df(vote_data$dados, function(v) {
      data.frame(
        bill_id = proposal_id,
        legislator_id = paste0("dep_", v$deputado_$id),
        vote = tolower(v$tipoVoto),
        vote_date = vote_date,
        session_number = votacao$siglaOrgao,
        stringsAsFactors = FALSE
      )
    })

    all_votes[[length(all_votes) + 1]] <- votes

    Sys.sleep(0.2)  # Rate limiting (optimized)
  }

  if (length(all_votes) == 0) {
    return(NULL)
  }

  bind_rows(all_votes)
}

#' Fetch Bill Events (Tramitação) for a Proposal
#'
#' @param proposal_id Integer. Câmara proposal ID
#' @param intro_date Date. Bill introduction date
#' @return Data frame with bill events
#' @export
fetch_bill_events <- function(proposal_id, intro_date) {
  base_url <- "https://dadosabertos.camara.leg.br/api/v2"
  endpoint <- sprintf("%s/proposicoes/%d/tramitacoes", base_url, proposal_id)

  response <- GET(endpoint)

  if (status_code(response) != 200) {
    return(data.frame())
  }

  data <- content(response, "parsed")

  if (length(data$dados) == 0) {
    return(data.frame())
  }

  events <- map_df(data$dados, function(tram) {
    event_date <- as.Date(tram$dataHora)
    days_since <- as.numeric(difftime(event_date, intro_date, units = "days"))

    # Map tramitação status to event types
    event_type <- case_when(
      grepl("apresenta|protocola", tolower(tram$despacho), ignore.case = TRUE) ~ "introduced",
      grepl("comiss", tolower(tram$despacho), ignore.case = TRUE) ~ "committee_assigned",
      grepl("aprovad|parecer favorável", tolower(tram$despacho), ignore.case = TRUE) ~ "committee_approved",
      grepl("rejeitad|parecer contrário", tolower(tram$despacho), ignore.case = TRUE) ~ "committee_rejected",
      grepl("plenário|ordem do dia", tolower(tram$despacho), ignore.case = TRUE) ~ "floor_scheduled",
      grepl("votação", tolower(tram$despacho), ignore.case = TRUE) ~ "floor_voted",
      grepl("sancionad|promulgad", tolower(tram$despacho), ignore.case = TRUE) ~ "enacted",
      grepl("arquivad|retirad", tolower(tram$despacho), ignore.case = TRUE) ~ "withdrawn",
      TRUE ~ NA_character_
    )

    if (is.na(event_type)) return(NULL)

    data.frame(
      bill_id = proposal_id,
      event_type = event_type,
      event_date = event_date,
      days_since_introduction = days_since,
      committee_name = tram$siglaOrgao,
      description = substr(tram$despacho, 1, 500),
      stringsAsFactors = FALSE
    )
  })

  events <- events %>%
    filter(!is.na(event_type)) %>%
    distinct(bill_id, event_type, event_date, .keep_all = TRUE)

  events
}

#' Fetch Recent Proposals from Câmara API
#'
#' @param limit Integer. Maximum number of proposals to fetch PER THEME
#' @param tema_codes Vector. Theme codes for filtering (default: c(61, 54, 41, 48, 40))
#' @return Data frame with proposal information
#' @export
fetch_recent_proposals <- function(limit = 200, tema_codes = c(61, 54, 41, 48, 40)) {
  cat(sprintf("\n=== Fetching Recent Proposals from %d Theme(s) ===\n", length(tema_codes)))
  cat(sprintf("Theme Codes: %s\n", paste(tema_codes, collapse=", ")))
  cat(sprintf("Limit per theme: %d bills\n\n", limit))

  base_url <- "https://dadosabertos.camara.leg.br/api/v2"
  endpoint <- sprintf("%s/proposicoes", base_url)

  # Fetch bills from each theme code
  all_bills <- data.frame()

  for (tema_code in tema_codes) {
    cat(sprintf("Fetching from Theme %d...\n", tema_code))

    # Filter by theme code
    # Order DESC by ID to get most recent bills first (today backwards)
    params <- list(
      codTema = tema_code,
      ordem = "DESC",
      ordenarPor = "id",
      itens = limit
    )

    response <- GET(endpoint, query = params)

    if (status_code(response) != 200) {
      warning(sprintf("API Error for theme %d: %d", tema_code, status_code(response)))
      next
    }

    data <- content(response, "parsed")

    if (length(data$dados) == 0) {
      cat(sprintf("No proposals found for theme %d\n", tema_code))
      next
    }

    proposals <- map_df(data$dados, function(prop) {
      data.frame(
        id = ifelse(is.null(prop$id), NA_integer_, prop$id),
        data_publicacao = ifelse(is.null(prop$dataApresentacao), NA_character_, prop$dataApresentacao),
        titulo = ifelse(is.null(prop$ementa), NA_character_, substr(prop$ementa, 1, 200)),
        stringsAsFactors = FALSE
      )
    })

    # Filter out NAs
    proposals <- proposals %>%
      filter(!is.na(id), !is.na(data_publicacao))

    cat(sprintf("✅ Fetched %d proposals from theme %d\n", nrow(proposals), tema_code))

    # Accumulate bills from this theme
    all_bills <- bind_rows(all_bills, proposals)
  }

  # Remove duplicates (same bill may appear in multiple themes)
  all_bills <- all_bills %>%
    distinct(id, .keep_all = TRUE)

  cat(sprintf("\n✅ Total unique bills across all themes: %d\n", nrow(all_bills)))

  return(all_bills)
}

#' Populate Legislators Table from API
#'
#' @param pool Database connection pool
#' @param legislature_id Integer. Legislature number
#' @export
populate_legislators_from_api <- function(pool, legislature_id = 57) {
  cat("\n")
  cat("==============================================================================\n")
  cat("POPULATING LEGISLATORS TABLE FROM API\n")
  cat("==============================================================================\n\n")

  # Fetch from both chambers
  camara_legs <- fetch_camara_legislators(legislature_id)
  senado_legs <- fetch_senado_legislators()

  # Combine and remove duplicates
  all_legislators <- bind_rows(camara_legs, senado_legs) %>%
    distinct(id, .keep_all = TRUE)

  if (nrow(all_legislators) == 0) {
    warning("No legislators fetched")
    return(0)
  }

  # Insert into database
  con <- poolCheckout(pool)
  on.exit(poolReturn(con))

  # Delete existing data
  dbExecute(con, "DELETE FROM legislators")
  cat("🗑️  Cleared existing legislators\n")

  # Insert new data
  dbWriteTable(con, "legislators", all_legislators, append = TRUE, row.names = FALSE)

  cat(sprintf("✅ Inserted %d legislators into database\n", nrow(all_legislators)))

  # Show summary
  summary <- all_legislators %>%
    count(party) %>%
    arrange(desc(n))

  cat("\n📊 Legislators by Party:\n")
  print(head(as.data.frame(summary), 10))

  return(nrow(all_legislators))
}

#' Populate Bill Events and Roll Call Votes from API
#'
#' @param pool Database connection pool
#' @param limit Integer. Maximum number of bills to process PER THEME
#' @export
populate_voting_data_from_api <- function(pool, limit = 200) {
  cat("\n")
  cat("==============================================================================\n")
  cat("POPULATING BILL EVENTS AND ROLL CALL VOTES FROM API\n")
  cat("==============================================================================\n")
  cat(sprintf("Limit per theme: %d bills\n", limit))
  cat("Themes: 61 (Transport), 54 (Energy), 41 (Cities), 48 (Environment), 40 (Economy)\n\n")

  # Fetch recent proposals from API (filtered by multiple themes)
  bills <- fetch_recent_proposals(limit)

  if (nrow(bills) == 0) {
    warning("No proposals found from API")
    return(list(events = 0, votes = 0))
  }

  cat(sprintf("📋 Processing %d bills...\n", nrow(bills)))
  cat("⚠️  NOTE: Only bills with recorded votes will be included in analysis\n\n")

  con <- poolCheckout(pool)
  on.exit(poolReturn(con))

  all_events <- list()
  all_votes <- list()
  processed <- 0
  skipped <- 0

  for (i in 1:nrow(bills)) {
    bill_id <- bills$id[i]
    intro_date <- as.Date(bills$data_publicacao[i])

    cat(sprintf("[%d/%d] Bill %d: %s\n", i, nrow(bills), bill_id, substr(bills$titulo[i], 1, 60)))

    # Fetch votes FIRST to check if bill has voting data
    has_votes <- FALSE
    tryCatch({
      votes <- fetch_proposal_votes(bill_id)
      if (!is.null(votes) && nrow(votes) > 0) {
        all_votes[[length(all_votes) + 1]] <- votes
        cat(sprintf("  ✅ %d votes\n", nrow(votes)))
        has_votes <- TRUE
      } else {
        cat("  ⏭️  No votes - skipping\n")
        skipped <- skipped + 1
      }
    }, error = function(e) {
      cat(sprintf("  ⚠️  Votes error: %s\n", e$message))
    })

    # Only fetch events if bill has votes
    if (has_votes) {
      tryCatch({
        events <- fetch_bill_events(bill_id, intro_date)
        if (nrow(events) > 0) {
          all_events[[length(all_events) + 1]] <- events
          cat(sprintf("  ✅ %d events\n", nrow(events)))
        }
      }, error = function(e) {
        cat(sprintf("  ⚠️  Events error: %s\n", e$message))
      })
    }

    processed <- processed + 1

    # Rate limiting (optimized)
    Sys.sleep(0.3)

    # Progress update every 10 bills
    if (i %% 10 == 0) {
      cat(sprintf("\n📊 Progress: %d/%d bills processed\n\n", i, nrow(bills)))
    }
  }

  # Insert events
  total_events <- 0
  if (length(all_events) > 0) {
    events_df <- bind_rows(all_events)

    # Clear existing events
    dbExecute(con, "DELETE FROM bill_events")
    cat("\n🗑️  Cleared existing bill events\n")

    # Insert new events
    dbWriteTable(con, "bill_events", events_df, append = TRUE, row.names = FALSE)
    total_events <- nrow(events_df)
    cat(sprintf("✅ Inserted %d bill events\n", total_events))
  }

  # Insert votes
  total_votes <- 0
  if (length(all_votes) > 0) {
    votes_df <- bind_rows(all_votes)

    # Clear existing votes
    dbExecute(con, "DELETE FROM roll_call_votes")
    cat("🗑️  Cleared existing roll call votes\n")

    # Insert new votes
    dbWriteTable(con, "roll_call_votes", votes_df, append = TRUE, row.names = FALSE)
    total_votes <- nrow(votes_df)
    cat(sprintf("✅ Inserted %d roll call votes\n", total_votes))
  }

  cat("\n")
  cat("==============================================================================\n")
  cat("DATA POPULATION COMPLETE\n")
  cat("==============================================================================\n")
  cat(sprintf("Bills Checked: %d\n", nrow(bills)))
  cat(sprintf("Bills with Votes: %d\n", processed))
  cat(sprintf("Bills Skipped (no votes): %d\n", skipped))
  cat(sprintf("Bill Events: %d\n", total_events))
  cat(sprintf("Roll Call Votes: %d\n", total_votes))
  cat("\n⚠️  IMPORTANT: Analysis includes only bills with recorded votes\n")
  cat("==============================================================================\n")

  return(list(events = total_events, votes = total_votes, bills = processed, skipped = skipped))
}

#' Main function to populate all Sprint 4 data from APIs
#'
#' @param pool Database connection pool
#' @param legislature_id Integer. Legislature number
#' @param bill_limit Integer. Maximum bills to process
#' @export
populate_sprint4_data <- function(pool, legislature_id = 57, bill_limit = 100) {
  cat("\n")
  cat("##############################################################################\n")
  cat("SPRINT 4: POPULATE PREDICTIVE ANALYTICS DATA FROM BRAZILIAN LEGISLATIVE APIs\n")
  cat("##############################################################################\n")
  cat(sprintf("Legislature: %d | Bills: %d (Transportation Theme)\n", legislature_id, bill_limit))
  cat("##############################################################################\n\n")

  start_time <- Sys.time()

  # Step 1: Populate legislators
  num_legislators <- populate_legislators_from_api(pool, legislature_id)

  # Step 2: Populate events and votes (filtered by transportation theme)
  voting_stats <- populate_voting_data_from_api(pool, bill_limit)

  end_time <- Sys.time()
  duration <- difftime(end_time, start_time, units = "mins")

  cat("\n")
  cat("##############################################################################\n")
  cat("POPULATION COMPLETE\n")
  cat("##############################################################################\n")
  cat(sprintf("Total Time: %.2f minutes\n", duration))
  cat(sprintf("Legislators: %d\n", num_legislators))
  cat(sprintf("Bill Events: %d\n", voting_stats$events))
  cat(sprintf("Roll Call Votes: %d\n", voting_stats$votes))
  cat(sprintf("Bills Processed: %d\n", voting_stats$bills))
  cat("##############################################################################\n\n")

  return(list(
    legislators = num_legislators,
    events = voting_stats$events,
    votes = voting_stats$votes,
    bills = voting_stats$bills,
    duration = duration
  ))
}
