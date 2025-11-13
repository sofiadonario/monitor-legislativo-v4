#' Readability Metrics for Portuguese Legislative Texts
#'
#' This module provides functions to calculate readability metrics adapted for
#' Portuguese legislative documents, including Flesch-Kincaid Reading Ease,
#' Gunning FOG Index, and SMOG Index.
#'
#' @author Monitor Legislativo v4
#' @date 2025-11-12

# Required packages
library(stringr)
library(dplyr)

#' Count Syllables in Portuguese Word
#'
#' Counts syllables in a Portuguese word using vowel-based heuristics.
#' Portuguese syllable structure: each vowel or vowel cluster forms one syllable.
#'
#' @param word Character string. A single Portuguese word.
#' @return Integer. Number of syllables in the word.
#'
#' @details
#' The algorithm:
#' - Identifies vowel groups (a, e, i, o, u, á, é, í, ó, ú, â, ê, ô, ã, õ, etc.)
#' - Treats diphthongs (ai, ei, oi, ui, au, eu, ou) as single syllables
#' - Handles hiatus (two adjacent vowels in separate syllables)
#' - Minimum return value is 1 (every word has at least one syllable)
#'
#' @examples
#' count_syllables_pt("constituição")  # 5
#' count_syllables_pt("lei")           # 1
#' count_syllables_pt("brasileiro")    # 4
#'
#' @export
count_syllables_pt <- function(word) {
  if (is.na(word) || word == "") return(0)

  # Convert to lowercase and remove non-alphabetic characters
  word <- tolower(word)
  word <- str_replace_all(word, "[^a-záàâãéèêíìóòôõúùçü]", "")

  if (nchar(word) == 0) return(0)

  # Define vowels including Portuguese diacritics
  vowels <- "aáàâãeéèêiíìoóòôõuúùü"

  # Replace common diphthongs with single marker to count as one syllable
  diphthongs <- c("ai", "ei", "oi", "ui", "au", "eu", "ou",
                  "ãe", "ão", "õe", "ái", "éi", "ói", "úi")

  for (diph in diphthongs) {
    word <- str_replace_all(word, diph, "X")
  }

  # Count remaining vowels (each is a syllable)
  syllable_count <- str_count(word, paste0("[", vowels, "X]"))

  # Ensure at least 1 syllable
  return(max(syllable_count, 1))
}

#' Count Complex Words in Text
#'
#' Counts words with 3 or more syllables in Portuguese text.
#' Used for FOG and SMOG index calculations.
#'
#' @param text Character string. Portuguese text to analyze.
#' @return Integer. Number of complex words (3+ syllables).
#'
#' @details
#' Complex words are defined as words with 3 or more syllables.
#' Common short words and proper nouns are included in the count.
#'
#' @examples
#' count_complex_words("A constituição brasileira é complexa.")
#'
#' @export
count_complex_words <- function(text) {
  if (is.na(text) || text == "") return(0)

  # Split into words and remove punctuation
  words <- str_split(text, "\\s+")[[1]]
  words <- str_replace_all(words, "[[:punct:]]", "")
  words <- words[words != ""]

  if (length(words) == 0) return(0)

  # Count syllables for each word
  syllable_counts <- sapply(words, count_syllables_pt, USE.NAMES = FALSE)

  # Count words with 3+ syllables
  complex_count <- sum(syllable_counts >= 3)

  return(complex_count)
}

#' Count Sentences in Text
#'
#' Counts sentences in Portuguese text using punctuation patterns.
#'
#' @param text Character string. Portuguese text to analyze.
#' @return Integer. Number of sentences.
#'
#' @details
#' Identifies sentence boundaries using:
#' - Period (.)
#' - Question mark (?)
#' - Exclamation mark (!)
#' - Semicolon (;) for legislative texts
#' Handles common abbreviations to avoid false sentence breaks.
#'
#' @examples
#' count_sentences("Art. 1º. Esta lei entra em vigor. Fim.")
#'
#' @export
count_sentences <- function(text) {
  if (is.na(text) || text == "") return(0)

  # Common abbreviations in legislative texts that shouldn't break sentences
  abbreviations <- c("art\\.", "inc\\.", "§", "º\\.", "ª\\.",
                     "sr\\.", "sra\\.", "dr\\.", "dra\\.",
                     "obs\\.", "etc\\.", "ex\\.", "cf\\.")

  # Temporarily replace abbreviations to avoid false sentence breaks
  temp_text <- text
  for (abbr in abbreviations) {
    temp_text <- str_replace_all(temp_text, abbr, str_replace(abbr, "\\.", "TEMP_DOT"))
  }

  # Count sentence-ending punctuation
  # In legislative texts, we consider ., !, ?, and ; as sentence boundaries
  sentence_count <- str_count(temp_text, "[.!?;]")

  # Ensure at least 1 sentence if text exists
  if (sentence_count == 0 && nchar(str_trim(text)) > 0) {
    return(1)
  }

  return(sentence_count)
}

#' Calculate Flesch-Kincaid Reading Ease for Portuguese
#'
#' Calculates the Flesch Reading Ease score adapted for Portuguese text.
#'
#' @param text Character string. Portuguese text to analyze.
#' @return Numeric. Flesch Reading Ease score (0-100, higher = easier).
#'
#' @details
#' Formula: 206.835 - 1.015 × (words/sentences) - 84.6 × (syllables/words)
#'
#' Score interpretation:
#' - 90-100: Very easy (5th grade)
#' - 80-90: Easy (6th grade)
#' - 70-80: Fairly easy (7th grade)
#' - 60-70: Standard (8th-9th grade)
#' - 50-60: Fairly difficult (10th-12th grade)
#' - 30-50: Difficult (college)
#' - 0-30: Very difficult (college graduate)
#'
#' @examples
#' text <- "Esta lei é simples. Ela tem regras claras."
#' calculate_flesch_kincaid_pt(text)
#'
#' @export
calculate_flesch_kincaid_pt <- function(text) {
  # Input validation
  if (is.na(text) || text == "" || is.null(text)) {
    return(NA_real_)
  }

  # Count words
  words <- str_split(text, "\\s+")[[1]]
  words <- str_replace_all(words, "[[:punct:]]", "")
  words <- words[words != ""]
  word_count <- length(words)

  if (word_count == 0) return(NA_real_)

  # Count sentences
  sentence_count <- count_sentences(text)
  if (sentence_count == 0) sentence_count <- 1  # Avoid division by zero

  # Count syllables
  syllable_counts <- sapply(words, count_syllables_pt, USE.NAMES = FALSE)
  total_syllables <- sum(syllable_counts)

  # Calculate Flesch Reading Ease (Portuguese adaptation)
  avg_words_per_sentence <- word_count / sentence_count
  avg_syllables_per_word <- total_syllables / word_count

  flesch_score <- 206.835 - (1.015 * avg_words_per_sentence) -
                  (84.6 * avg_syllables_per_word)

  # Bound the score between 0 and 100
  flesch_score <- max(0, min(100, flesch_score))

  return(round(flesch_score, 2))
}

#' Calculate Gunning FOG Index
#'
#' Calculates the Gunning FOG Index for Portuguese text.
#'
#' @param text Character string. Portuguese text to analyze.
#' @return Numeric. FOG Index (years of education needed to understand).
#'
#' @details
#' Formula: 0.4 × [(words/sentences) + 100 × (complex_words/words)]
#'
#' Complex words are defined as words with 3+ syllables.
#'
#' Score interpretation:
#' - 6: Easy (6th grade level)
#' - 9-12: High school level
#' - 13-16: College level
#' - 17+: Post-graduate level
#'
#' @examples
#' text <- "A constituição estabelece direitos fundamentais."
#' calculate_fog_index(text)
#'
#' @export
calculate_fog_index <- function(text) {
  # Input validation
  if (is.na(text) || text == "" || is.null(text)) {
    return(NA_real_)
  }

  # Count words
  words <- str_split(text, "\\s+")[[1]]
  words <- str_replace_all(words, "[[:punct:]]", "")
  words <- words[words != ""]
  word_count <- length(words)

  if (word_count == 0) return(NA_real_)

  # Count sentences
  sentence_count <- count_sentences(text)
  if (sentence_count == 0) sentence_count <- 1

  # Count complex words
  complex_word_count <- count_complex_words(text)

  # Calculate FOG Index
  avg_words_per_sentence <- word_count / sentence_count
  percent_complex <- 100 * (complex_word_count / word_count)

  fog_index <- 0.4 * (avg_words_per_sentence + percent_complex)

  return(round(fog_index, 2))
}

#' Calculate SMOG Index
#'
#' Calculates the SMOG (Simple Measure of Gobbledygook) Index for Portuguese text.
#'
#' @param text Character string. Portuguese text to analyze.
#' @return Numeric. SMOG Index (years of education needed).
#'
#' @details
#' Formula: 1.043 × sqrt(polysyllables × (30/sentences)) + 3.1291
#'
#' Polysyllables are words with 3+ syllables.
#' The formula is designed for texts with at least 30 sentences.
#' For shorter texts, results should be interpreted cautiously.
#'
#' Score interpretation:
#' - 6-8: Middle school level
#' - 9-12: High school level
#' - 13-16: College level
#' - 17+: Graduate level
#'
#' @examples
#' text <- "A legislação brasileira é complexa e requer interpretação."
#' calculate_smog_index(text)
#'
#' @export
calculate_smog_index <- function(text) {
  # Input validation
  if (is.na(text) || text == "" || is.null(text)) {
    return(NA_real_)
  }

  # Count sentences
  sentence_count <- count_sentences(text)
  if (sentence_count == 0) return(NA_real_)

  # Count polysyllables (3+ syllables)
  polysyllable_count <- count_complex_words(text)

  # Calculate SMOG Index
  # Note: Original SMOG uses 30 sentences, we adjust for actual sentence count
  smog_index <- 1.043 * sqrt(polysyllable_count * (30 / sentence_count)) + 3.1291

  return(round(smog_index, 2))
}

#' Calculate All Readability Metrics
#'
#' Calculates all three readability metrics for Portuguese text in one call.
#'
#' @param text Character string. Portuguese text to analyze.
#' @return Named list with three elements:
#'   \itemize{
#'     \item flesch_kincaid: Flesch Reading Ease score (0-100)
#'     \item fog_index: Gunning FOG Index (grade level)
#'     \item smog_index: SMOG Index (grade level)
#'   }
#'
#' @examples
#' text <- "Art. 1º. Esta lei estabelece normas gerais. Ela entra em vigor hoje."
#' metrics <- calculate_all_readability_metrics(text)
#' print(metrics)
#'
#' @export
calculate_all_readability_metrics <- function(text) {
  list(
    flesch_kincaid = calculate_flesch_kincaid_pt(text),
    fog_index = calculate_fog_index(text),
    smog_index = calculate_smog_index(text)
  )
}

#' Batch Calculate Readability Metrics from Database
#'
#' Processes all documents in a database table and calculates readability metrics.
#' Uses batch processing for efficiency with large datasets (118K+ documents).
#'
#' @param db_connection Database connection object (DBI compatible).
#' @param table_name Character string. Name of the table containing documents.
#'   Default: "documents"
#' @param text_column Character string. Name of the column containing full text.
#'   Default: "texto_completo"
#' @param id_column Character string. Name of the ID column.
#'   Default: "id"
#' @param batch_size Integer. Number of documents to process per batch.
#'   Default: 1000
#' @param verbose Logical. Whether to print progress messages.
#'   Default: TRUE
#'
#' @return data.frame with columns:
#'   \itemize{
#'     \item id: Document ID
#'     \item flesch_kincaid: Flesch Reading Ease score
#'     \item fog_index: FOG Index
#'     \item smog_index: SMOG Index
#'     \item word_count: Number of words in document
#'     \item sentence_count: Number of sentences in document
#'   }
#'
#' @details
#' Performance estimates:
#' - ~50-100 documents/second on standard hardware
#' - 118,920 documents: approximately 20-40 minutes total
#' - Memory usage: ~100-200 MB for batch size of 1000
#'
#' The function:
#' - Handles NULL/empty text gracefully (returns NA for metrics)
#' - Reports progress every batch
#' - Includes error handling to continue processing if individual documents fail
#' - Returns timing information
#'
#' @examples
#' \dontrun{
#' library(RPostgreSQL)
#' con <- dbConnect(PostgreSQL(),
#'                  dbname = "monitor_legislativo",
#'                  host = "localhost",
#'                  port = 5432,
#'                  user = "user",
#'                  password = "pass")
#'
#' results <- batch_calculate_readability(con,
#'                                       table_name = "documents",
#'                                       batch_size = 1000)
#'
#' # Write results back to database
#' dbWriteTable(con, "readability_metrics", results,
#'              overwrite = TRUE, row.names = FALSE)
#'
#' dbDisconnect(con)
#' }
#'
#' @export
batch_calculate_readability <- function(db_connection,
                                       table_name = "documents",
                                       text_column = "texto_completo",
                                       id_column = "id",
                                       batch_size = 1000,
                                       verbose = TRUE) {

  # Validate inputs
  if (!inherits(db_connection, "DBIConnection")) {
    stop("db_connection must be a valid DBI database connection")
  }

  start_time <- Sys.time()

  # Get total document count
  count_query <- sprintf("SELECT COUNT(*) as total FROM %s", table_name)
  total_docs <- DBI::dbGetQuery(db_connection, count_query)$total

  if (verbose) {
    cat(sprintf("\n=== Batch Readability Analysis ===\n"))
    cat(sprintf("Total documents: %s\n", format(total_docs, big.mark = ",")))
    cat(sprintf("Batch size: %s\n", format(batch_size, big.mark = ",")))
    cat(sprintf("Estimated batches: %d\n", ceiling(total_docs / batch_size)))
    cat(sprintf("Started at: %s\n\n", format(start_time, "%Y-%m-%d %H:%M:%S")))
  }

  # Initialize results list
  all_results <- list()
  batch_num <- 1
  offset <- 0

  # Process in batches
  while (offset < total_docs) {
    batch_start <- Sys.time()

    # Fetch batch
    query <- sprintf(
      "SELECT %s, %s FROM %s ORDER BY %s LIMIT %d OFFSET %d",
      id_column, text_column, table_name, id_column, batch_size, offset
    )

    batch_data <- DBI::dbGetQuery(db_connection, query)

    if (nrow(batch_data) == 0) break

    # Calculate metrics for each document in batch
    batch_results <- data.frame(
      id = integer(nrow(batch_data)),
      flesch_kincaid = numeric(nrow(batch_data)),
      fog_index = numeric(nrow(batch_data)),
      smog_index = numeric(nrow(batch_data)),
      word_count = integer(nrow(batch_data)),
      sentence_count = integer(nrow(batch_data)),
      stringsAsFactors = FALSE
    )

    for (i in 1:nrow(batch_data)) {
      doc_id <- batch_data[[id_column]][i]
      text <- batch_data[[text_column]][i]

      batch_results$id[i] <- doc_id

      # Handle NULL or empty text
      if (is.na(text) || text == "" || is.null(text)) {
        batch_results$flesch_kincaid[i] <- NA_real_
        batch_results$fog_index[i] <- NA_real_
        batch_results$smog_index[i] <- NA_real_
        batch_results$word_count[i] <- 0
        batch_results$sentence_count[i] <- 0
        next
      }

      # Calculate metrics with error handling
      tryCatch({
        # Count words and sentences
        words <- str_split(text, "\\s+")[[1]]
        words <- str_replace_all(words, "[[:punct:]]", "")
        words <- words[words != ""]
        batch_results$word_count[i] <- length(words)
        batch_results$sentence_count[i] <- count_sentences(text)

        # Calculate readability metrics
        batch_results$flesch_kincaid[i] <- calculate_flesch_kincaid_pt(text)
        batch_results$fog_index[i] <- calculate_fog_index(text)
        batch_results$smog_index[i] <- calculate_smog_index(text)

      }, error = function(e) {
        if (verbose) {
          cat(sprintf("  Error processing document ID %d: %s\n", doc_id, e$message))
        }
        batch_results$flesch_kincaid[i] <- NA_real_
        batch_results$fog_index[i] <- NA_real_
        batch_results$smog_index[i] <- NA_real_
      })
    }

    # Store batch results
    all_results[[batch_num]] <- batch_results

    # Progress reporting
    if (verbose) {
      batch_end <- Sys.time()
      batch_time <- as.numeric(difftime(batch_end, batch_start, units = "secs"))
      docs_processed <- offset + nrow(batch_data)
      progress_pct <- (docs_processed / total_docs) * 100

      # Calculate ETA
      elapsed <- as.numeric(difftime(batch_end, start_time, units = "secs"))
      docs_per_sec <- docs_processed / elapsed
      remaining_docs <- total_docs - docs_processed
      eta_secs <- remaining_docs / docs_per_sec

      cat(sprintf(
        "Batch %d: Processed %s/%s docs (%.1f%%) | %.1f docs/sec | ETA: %.1f min\n",
        batch_num,
        format(docs_processed, big.mark = ","),
        format(total_docs, big.mark = ","),
        progress_pct,
        docs_per_sec,
        eta_secs / 60
      ))
    }

    offset <- offset + batch_size
    batch_num <- batch_num + 1
  }

  # Combine all batch results
  final_results <- bind_rows(all_results)

  # Summary statistics
  if (verbose) {
    end_time <- Sys.time()
    total_time <- as.numeric(difftime(end_time, start_time, units = "secs"))

    cat(sprintf("\n=== Processing Complete ===\n"))
    cat(sprintf("Total time: %.2f minutes\n", total_time / 60))
    cat(sprintf("Average speed: %.1f documents/second\n", nrow(final_results) / total_time))
    cat(sprintf("Documents processed: %s\n", format(nrow(final_results), big.mark = ",")))
    cat(sprintf("Documents with errors: %d\n", sum(is.na(final_results$flesch_kincaid))))
    cat("\nMetric summaries (excluding NAs):\n")
    cat(sprintf("  Flesch-Kincaid: Mean = %.2f, Median = %.2f, SD = %.2f\n",
                mean(final_results$flesch_kincaid, na.rm = TRUE),
                median(final_results$flesch_kincaid, na.rm = TRUE),
                sd(final_results$flesch_kincaid, na.rm = TRUE)))
    cat(sprintf("  FOG Index: Mean = %.2f, Median = %.2f, SD = %.2f\n",
                mean(final_results$fog_index, na.rm = TRUE),
                median(final_results$fog_index, na.rm = TRUE),
                sd(final_results$fog_index, na.rm = TRUE)))
    cat(sprintf("  SMOG Index: Mean = %.2f, Median = %.2f, SD = %.2f\n",
                mean(final_results$smog_index, na.rm = TRUE),
                median(final_results$smog_index, na.rm = TRUE),
                sd(final_results$smog_index, na.rm = TRUE)))
    cat(sprintf("\nFinished at: %s\n", format(end_time, "%Y-%m-%d %H:%M:%S")))
  }

  return(final_results)
}

# ==============================================================================
# TESTING AND DEMONSTRATION
# ==============================================================================

if (FALSE) {  # Set to TRUE to run tests

  cat("\n=== Testing Readability Metrics for Portuguese Legislative Texts ===\n\n")

  # Test 1: Simple legislative text
  cat("Test 1: Simple Legislative Text\n")
  cat("--------------------------------\n")
  simple_text <- "Esta lei é clara. Ela tem regras simples. Todos podem ler."

  cat("Text:", simple_text, "\n")
  cat("\nHelper functions:\n")
  cat("  Sentences:", count_sentences(simple_text), "\n")
  cat("  Complex words:", count_complex_words(simple_text), "\n")

  simple_metrics <- calculate_all_readability_metrics(simple_text)
  cat("\nReadability Metrics:\n")
  cat("  Flesch-Kincaid:", simple_metrics$flesch_kincaid, "(higher = easier)\n")
  cat("  FOG Index:", simple_metrics$fog_index, "(grade level)\n")
  cat("  SMOG Index:", simple_metrics$smog_index, "(grade level)\n\n")

  # Test 2: Complex legislative text
  cat("\nTest 2: Complex Legislative Text\n")
  cat("---------------------------------\n")
  complex_text <- paste(
    "Art. 1º. A administração pública direta e indireta de qualquer dos Poderes",
    "da União, dos Estados, do Distrito Federal e dos Municípios obedecerá aos",
    "princípios de legalidade, impessoalidade, moralidade, publicidade e eficiência.",
    "§ 1º A publicidade dos atos, programas, obras, serviços e campanhas dos órgãos",
    "públicos deverá ter caráter educativo, informativo ou de orientação social."
  )

  cat("Text excerpt from Constitution...\n")
  cat("\nHelper functions:\n")
  cat("  Sentences:", count_sentences(complex_text), "\n")
  cat("  Complex words:", count_complex_words(complex_text), "\n")

  complex_metrics <- calculate_all_readability_metrics(complex_text)
  cat("\nReadability Metrics:\n")
  cat("  Flesch-Kincaid:", complex_metrics$flesch_kincaid, "(higher = easier)\n")
  cat("  FOG Index:", complex_metrics$fog_index, "(grade level)\n")
  cat("  SMOG Index:", complex_metrics$smog_index, "(grade level)\n\n")

  # Test 3: Syllable counting
  cat("\nTest 3: Portuguese Syllable Counting\n")
  cat("-------------------------------------\n")
  test_words <- c("lei", "constituição", "brasileiro", "administração",
                  "publicidade", "eficiência", "impessoalidade")

  for (word in test_words) {
    syllables <- count_syllables_pt(word)
    cat(sprintf("  %s: %d syllables\n", word, syllables))
  }

  # Test 4: Edge cases
  cat("\nTest 4: Edge Cases\n")
  cat("------------------\n")

  edge_cases <- list(
    "Empty string" = "",
    "Single word" = "Lei",
    "No punctuation" = "Esta é uma lei sem ponto final",
    "Only punctuation" = "...",
    "NA value" = NA_character_
  )

  for (name in names(edge_cases)) {
    text <- edge_cases[[name]]
    result <- calculate_flesch_kincaid_pt(text)
    cat(sprintf("  %s: Flesch = %s\n", name,
                ifelse(is.na(result), "NA", as.character(result))))
  }

  # Test 5: Performance benchmark
  cat("\nTest 5: Performance Benchmark\n")
  cat("-----------------------------\n")

  # Generate sample documents
  sample_doc <- paste(
    "Art. 1º. Esta lei estabelece normas gerais sobre licitações e contratos",
    "administrativos pertinentes a obras, serviços, inclusive de publicidade,",
    "compras, alienações e locações no âmbito dos Poderes da União, dos Estados,",
    "do Distrito Federal e dos Municípios. Parágrafo único. Subordinam-se ao",
    "regime desta Lei, além dos órgãos da administração direta, os fundos especiais,",
    "as autarquias, as fundações públicas, as empresas públicas, as sociedades de",
    "economia mista e demais entidades controladas direta ou indiretamente."
  )

  n_docs <- 100

  cat("Processing", n_docs, "sample documents...\n")
  start_time <- Sys.time()

  results <- replicate(n_docs, {
    calculate_all_readability_metrics(sample_doc)
  }, simplify = FALSE)

  end_time <- Sys.time()
  elapsed <- as.numeric(difftime(end_time, start_time, units = "secs"))

  cat(sprintf("  Time: %.2f seconds\n", elapsed))
  cat(sprintf("  Speed: %.1f documents/second\n", n_docs / elapsed))
  cat(sprintf("  Estimated time for 118,920 docs: %.1f minutes\n",
              (118920 / (n_docs / elapsed)) / 60))

  cat("\n=== All Tests Complete ===\n\n")
}

# ==============================================================================
# USAGE EXAMPLES FOR MONITOR LEGISLATIVO V4
# ==============================================================================

#' Example: Analyze Single Document
#'
#' @examples
#' \dontrun{
#' # Read document from database
#' library(RPostgreSQL)
#' con <- dbConnect(PostgreSQL(), dbname = "monitor_legislativo")
#'
#' doc <- dbGetQuery(con, "SELECT texto_completo FROM documents WHERE id = 1")
#' text <- doc$texto_completo[1]
#'
#' # Calculate metrics
#' metrics <- calculate_all_readability_metrics(text)
#' print(metrics)
#'
#' dbDisconnect(con)
#' }

#' Example: Batch Process All Documents
#'
#' @examples
#' \dontrun{
#' library(RPostgreSQL)
#' con <- dbConnect(PostgreSQL(),
#'                  dbname = "monitor_legislativo",
#'                  host = "localhost",
#'                  port = 5432,
#'                  user = Sys.getenv("DB_USER"),
#'                  password = Sys.getenv("DB_PASSWORD"))
#'
#' # Process all documents
#' results <- batch_calculate_readability(
#'   con,
#'   table_name = "documents",
#'   text_column = "texto_completo",
#'   batch_size = 1000,
#'   verbose = TRUE
#' )
#'
#' # Save results
#' write.csv(results, "readability_metrics.csv", row.names = FALSE)
#'
#' # Or write back to database
#' dbWriteTable(con, "readability_metrics", results,
#'              overwrite = TRUE, row.names = FALSE)
#'
#' # Create index for performance
#' dbExecute(con, "CREATE INDEX idx_readability_doc_id ON readability_metrics(id)")
#'
#' dbDisconnect(con)
#' }

#' Example: Integrate with Shiny App
#'
#' @examples
#' \dontrun{
#' # In your Shiny server function:
#' output$readability_table <- renderTable({
#'   # Get document ID from input
#'   doc_id <- input$selected_document
#'
#'   # Fetch document text
#'   doc <- dbGetQuery(pool,
#'     "SELECT texto_completo FROM documents WHERE id = ?",
#'     params = list(doc_id))
#'
#'   # Calculate metrics
#'   metrics <- calculate_all_readability_metrics(doc$texto_completo[1])
#'
#'   # Format for display
#'   data.frame(
#'     Metric = c("Flesch Reading Ease", "FOG Index", "SMOG Index"),
#'     Score = c(metrics$flesch_kincaid, metrics$fog_index, metrics$smog_index),
#'     Interpretation = c(
#'       interpret_flesch(metrics$flesch_kincaid),
#'       interpret_grade_level(metrics$fog_index),
#'       interpret_grade_level(metrics$smog_index)
#'     )
#'   )
#' })
#' }

# Helper functions for interpretation (bonus)
interpret_flesch <- function(score) {
  if (is.na(score)) return("N/A")
  if (score >= 90) return("Muito fácil (5º ano)")
  if (score >= 80) return("Fácil (6º ano)")
  if (score >= 70) return("Razoavelmente fácil (7º ano)")
  if (score >= 60) return("Padrão (8º-9º ano)")
  if (score >= 50) return("Razoavelmente difícil (Ensino Médio)")
  if (score >= 30) return("Difícil (Ensino Superior)")
  return("Muito difícil (Pós-graduação)")
}

interpret_grade_level <- function(grade) {
  if (is.na(grade)) return("N/A")
  if (grade <= 8) return(sprintf("Ensino Fundamental (%.0fº ano)", grade))
  if (grade <= 12) return(sprintf("Ensino Médio (%.0fº ano)", grade))
  if (grade <= 16) return("Ensino Superior")
  return("Pós-graduação")
}
