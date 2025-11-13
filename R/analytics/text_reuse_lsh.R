#' Text Reuse Detection using Locality-Sensitive Hashing
#'
#' Efficient text similarity detection across 118k+ legislative documents
#' using MinHash signatures and LSH indexing.
#'
#' @author Monitor Legislativo Analytics Team
#' @date 2025-01-13

library(DBI)
library(textreuse)
library(digest)
library(dplyr)
library(stringr)
library(data.table)

# ============================================================================
# CORE LSH FUNCTIONS
# ============================================================================

#' Create k-gram shingles from text
#'
#' @param text Character vector of document text
#' @param k Integer, shingle size (default 5 for word-level shingles)
#' @return Character vector of unique shingles
#' @export
create_shingles <- function(text, k = 5) {
  if (is.null(text) || length(text) == 0 || is.na(text) || nchar(text) == 0) {
    return(character(0))
  }

  # Normalize text: lowercase, remove extra whitespace
  text <- tolower(text)
  text <- str_squish(text)

  # Tokenize into words
  words <- unlist(str_split(text, "\\s+"))

  # Create k-grams
  if (length(words) < k) {
    # If document too short, use what we have
    return(paste(words, collapse = " "))
  }

  shingles <- character(length(words) - k + 1)
  for (i in 1:(length(words) - k + 1)) {
    shingles[i] <- paste(words[i:(i + k - 1)], collapse = " ")
  }

  # Return unique shingles
  unique(shingles)
}

#' Create MinHash signature for a set of shingles
#'
#' @param shingles Character vector of shingles
#' @param num_hashes Integer, number of hash functions (default 100)
#' @param seed Integer, random seed for reproducibility
#' @return Integer vector of MinHash signature
#' @export
minhash_signature <- function(shingles, num_hashes = 100, seed = 42) {
  if (length(shingles) == 0) {
    return(rep(as.integer(NA), num_hashes))
  }

  # Initialize signature with maximum integer value
  signature <- rep(.Machine$integer.max, num_hashes)

  # For each shingle, compute num_hashes different hash values
  for (shingle in shingles) {
    for (h in 1:num_hashes) {
      # Create unique hash by combining shingle with hash function index
      hash_input <- paste0(shingle, "_", h, "_", seed)
      hash_value <- digest(hash_input, algo = "xxhash32", serialize = FALSE)
      # Convert hex to integer
      hash_int <- as.integer(paste0("0x", substr(hash_value, 1, 8)))

      # MinHash: keep minimum hash value
      if (hash_int < signature[h]) {
        signature[h] <- hash_int
      }
    }
  }

  signature
}

#' Compute Jaccard similarity from MinHash signatures
#'
#' @param sig1 Integer vector, first signature
#' @param sig2 Integer vector, second signature
#' @return Numeric, estimated Jaccard similarity (0-1)
#' @export
estimate_jaccard <- function(sig1, sig2) {
  if (length(sig1) != length(sig2)) {
    stop("Signatures must have same length")
  }

  # Handle NA signatures
  if (any(is.na(sig1)) || any(is.na(sig2))) {
    return(0.0)
  }

  # Fraction of matching hash values
  sum(sig1 == sig2) / length(sig1)
}

#' Create LSH bucket hash for a band
#'
#' @param signature_band Integer vector, portion of signature
#' @return Character, bucket hash
lsh_bucket_hash <- function(signature_band) {
  digest(paste(signature_band, collapse = "_"), algo = "md5", serialize = FALSE)
}

# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

#' Index all documents with LSH
#'
#' @param db_connection Database connection
#' @param batch_size Integer, documents per batch
#' @param bands Integer, number of LSH bands
#' @param rows_per_band Integer, rows per band
#' @param k Integer, shingle size
#' @param num_hashes Integer, number of hash functions
#' @param max_docs Integer, maximum documents to process (NULL for all)
#' @return List with indexing statistics
#' @export
lsh_index_documents <- function(db_connection,
                                 batch_size = 1000,
                                 bands = 20,
                                 rows_per_band = 5,
                                 k = 5,
                                 num_hashes = 100,
                                 max_docs = NULL) {

  cat("Starting LSH indexing...\n")
  start_time <- Sys.time()

  # Verify parameters
  if (bands * rows_per_band != num_hashes) {
    stop("bands * rows_per_band must equal num_hashes")
  }

  # Get total document count
  if (is.null(max_docs)) {
    count_query <- "SELECT COUNT(*) as n FROM documents WHERE texto_completo IS NOT NULL AND texto_completo != ''"
  } else {
    count_query <- sprintf("SELECT COUNT(*) as n FROM (SELECT id FROM documents WHERE texto_completo IS NOT NULL AND texto_completo != '' LIMIT %d) sub", max_docs)
  }
  total_docs <- dbGetQuery(db_connection, count_query)$n
  cat(sprintf("Processing %d documents\n", total_docs))

  # Process in batches
  processed <- 0
  skipped <- 0

  for (offset in seq(0, total_docs - 1, batch_size)) {
    if (is.null(max_docs)) {
      query <- sprintf(
        "SELECT id, texto_completo FROM documents
         WHERE texto_completo IS NOT NULL AND texto_completo != ''
         ORDER BY id LIMIT %d OFFSET %d",
        batch_size, offset
      )
    } else {
      query <- sprintf(
        "SELECT id, texto_completo FROM documents
         WHERE texto_completo IS NOT NULL AND texto_completo != ''
         ORDER BY id LIMIT %d OFFSET %d",
        min(batch_size, max_docs - offset), offset
      )
    }

    docs <- dbGetQuery(db_connection, query)

    if (nrow(docs) == 0) break

    # Process each document
    for (i in 1:nrow(docs)) {
      doc_id <- docs$id[i]
      text <- docs$texto_completo[i]

      # Create shingles
      shingles <- create_shingles(text, k = k)

      if (length(shingles) == 0) {
        skipped <- skipped + 1
        next
      }

      # Create MinHash signature
      signature <- minhash_signature(shingles, num_hashes = num_hashes)

      # Store signature in database
      sig_bytes <- serialize(signature, NULL)

      dbExecute(db_connection,
        "INSERT INTO text_reuse_signatures (document_id, signature, num_shingles)
         VALUES ($1, $2, $3)
         ON CONFLICT (document_id) DO UPDATE
         SET signature = EXCLUDED.signature,
             num_shingles = EXCLUDED.num_shingles,
             created_at = CURRENT_TIMESTAMP",
        params = list(doc_id, list(sig_bytes), length(shingles))
      )

      # Create LSH buckets
      for (band in 1:bands) {
        start_idx <- (band - 1) * rows_per_band + 1
        end_idx <- band * rows_per_band
        band_sig <- signature[start_idx:end_idx]
        bucket <- lsh_bucket_hash(band_sig)

        dbExecute(db_connection,
          "INSERT INTO lsh_buckets (band_number, bucket_hash, document_id)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING",
          params = list(band, bucket, doc_id)
        )
      }

      processed <- processed + 1
    }

    # Progress report
    pct <- round(100 * (offset + nrow(docs)) / total_docs, 1)
    elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    rate <- processed / elapsed
    cat(sprintf("Progress: %d/%d (%.1f%%) | Rate: %.1f docs/sec | Skipped: %d\n",
                offset + nrow(docs), total_docs, pct, rate, skipped))
  }

  end_time <- Sys.time()
  elapsed_total <- as.numeric(difftime(end_time, start_time, units = "mins"))

  # Return statistics
  list(
    documents_processed = processed,
    documents_skipped = skipped,
    elapsed_minutes = elapsed_total,
    docs_per_second = processed / (elapsed_total * 60),
    bands = bands,
    rows_per_band = rows_per_band,
    num_hashes = num_hashes,
    shingle_size = k
  )
}

#' Find documents similar to a given document
#'
#' @param db_connection Database connection
#' @param document_id Integer, focal document ID
#' @param threshold Numeric, minimum Jaccard similarity (0-1)
#' @param max_results Integer, maximum results to return
#' @return Data frame with similar documents
#' @export
find_similar_documents <- function(db_connection,
                                    document_id,
                                    threshold = 0.7,
                                    max_results = 100) {

  # Get focal document signature
  sig_query <- "SELECT signature FROM text_reuse_signatures WHERE document_id = $1"
  sig_result <- dbGetQuery(db_connection, sig_query, params = list(document_id))

  if (nrow(sig_result) == 0) {
    stop("Document not indexed. Run lsh_index_documents first.")
  }

  focal_sig <- unserialize(sig_result$signature[[1]])

  # Find candidate documents from LSH buckets
  candidate_query <- "
    SELECT DISTINCT lb.document_id
    FROM lsh_buckets lb
    WHERE lb.bucket_hash IN (
      SELECT bucket_hash
      FROM lsh_buckets
      WHERE document_id = $1
    )
    AND lb.document_id != $1
  "

  candidates <- dbGetQuery(db_connection, candidate_query, params = list(document_id))

  if (nrow(candidates) == 0) {
    return(data.frame(
      similar_doc_id = integer(0),
      jaccard_similarity = numeric(0),
      num_shingles = integer(0),
      titulo = character(0),
      ano = integer(0),
      nivel = character(0)
    ))
  }

  # Retrieve signatures for all candidates
  sig_query <- sprintf(
    "SELECT document_id, signature FROM text_reuse_signatures WHERE document_id IN (%s)",
    paste(candidates$document_id, collapse = ",")
  )
  candidate_sigs <- dbGetQuery(db_connection, sig_query)

  # Compute actual Jaccard similarities
  similarities <- data.frame(
    similar_doc_id = integer(0),
    jaccard_similarity = numeric(0)
  )

  for (i in 1:nrow(candidate_sigs)) {
    cand_sig <- unserialize(candidate_sigs$signature[[i]])
    jaccard <- estimate_jaccard(focal_sig, cand_sig)

    if (jaccard >= threshold) {
      similarities <- rbind(similarities, data.frame(
        similar_doc_id = candidate_sigs$document_id[i],
        jaccard_similarity = jaccard
      ))
    }
  }

  if (nrow(similarities) == 0) {
    return(data.frame(
      similar_doc_id = integer(0),
      jaccard_similarity = numeric(0),
      num_shingles = integer(0),
      titulo = character(0),
      ano = integer(0),
      nivel = character(0)
    ))
  }

  # Join with document metadata
  doc_query <- sprintf(
    "SELECT d.id, d.titulo, d.ano, d.nivel, s.num_shingles
     FROM documents d
     JOIN text_reuse_signatures s ON d.id = s.document_id
     WHERE d.id IN (%s)",
    paste(similarities$similar_doc_id, collapse = ",")
  )
  doc_info <- dbGetQuery(db_connection, doc_query)

  # Merge and sort
  result <- similarities %>%
    left_join(doc_info, by = c("similar_doc_id" = "id")) %>%
    arrange(desc(jaccard_similarity)) %>%
    head(max_results)

  result
}

#' Detect all similar document pairs above threshold
#'
#' @param db_connection Database connection
#' @param threshold Numeric, minimum Jaccard similarity
#' @param store_results Logical, store in text_reuse_pairs table
#' @return Data frame of similar pairs
#' @export
detect_all_similar_pairs <- function(db_connection,
                                      threshold = 0.7,
                                      store_results = TRUE) {

  cat("Detecting similar document pairs...\n")
  start_time <- Sys.time()

  if (store_results) {
    # Clear existing pairs at this threshold
    dbExecute(db_connection, "DELETE FROM text_reuse_pairs WHERE jaccard_similarity >= $1",
              params = list(threshold))
  }

  # Get all unique bucket groups with multiple documents
  bucket_query <- "
    SELECT band_number, bucket_hash, array_agg(document_id ORDER BY document_id) as doc_ids
    FROM lsh_buckets
    GROUP BY band_number, bucket_hash
    HAVING COUNT(*) > 1
  "

  buckets <- dbGetQuery(db_connection, bucket_query)
  cat(sprintf("Found %d buckets with multiple documents\n", nrow(buckets)))

  # Process each bucket to find similar pairs
  all_pairs <- list()
  pair_count <- 0

  for (i in 1:nrow(buckets)) {
    doc_ids <- buckets$doc_ids[[i]]

    if (length(doc_ids) < 2) next

    # Get signatures for all docs in bucket
    sig_query <- sprintf(
      "SELECT document_id, signature FROM text_reuse_signatures WHERE document_id IN (%s)",
      paste(doc_ids, collapse = ",")
    )
    sigs <- dbGetQuery(db_connection, sig_query)

    # Compare all pairs
    for (j in 1:(nrow(sigs) - 1)) {
      for (k in (j + 1):nrow(sigs)) {
        doc1 <- sigs$document_id[j]
        doc2 <- sigs$document_id[k]

        # Skip if already compared
        pair_key <- paste(sort(c(doc1, doc2)), collapse = "_")
        if (pair_key %in% names(all_pairs)) next

        sig1 <- unserialize(sigs$signature[[j]])
        sig2 <- unserialize(sigs$signature[[k]])

        jaccard <- estimate_jaccard(sig1, sig2)

        if (jaccard >= threshold) {
          all_pairs[[pair_key]] <- data.frame(
            doc1_id = min(doc1, doc2),
            doc2_id = max(doc1, doc2),
            jaccard_similarity = jaccard
          )
          pair_count <- pair_count + 1

          if (store_results) {
            dbExecute(db_connection,
              "INSERT INTO text_reuse_pairs (doc1_id, doc2_id, jaccard_similarity)
               VALUES ($1, $2, $3)
               ON CONFLICT DO NOTHING",
              params = list(min(doc1, doc2), max(doc1, doc2), jaccard)
            )
          }
        }
      }
    }

    if (i %% 100 == 0) {
      cat(sprintf("Processed %d/%d buckets, found %d pairs\n", i, nrow(buckets), pair_count))
    }
  }

  elapsed <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
  cat(sprintf("Completed in %.1f minutes. Found %d similar pairs.\n", elapsed, pair_count))

  if (length(all_pairs) == 0) {
    return(data.frame(
      doc1_id = integer(0),
      doc2_id = integer(0),
      jaccard_similarity = numeric(0)
    ))
  }

  do.call(rbind, all_pairs)
}

#' Detect clusters of similar documents
#'
#' @param db_connection Database connection
#' @param min_cluster_size Integer, minimum cluster size
#' @param threshold Numeric, similarity threshold
#' @return List of clusters
#' @export
detect_text_reuse_clusters <- function(db_connection,
                                        min_cluster_size = 3,
                                        threshold = 0.7) {

  # Get all similar pairs
  pairs_query <- sprintf(
    "SELECT doc1_id, doc2_id, jaccard_similarity
     FROM text_reuse_pairs
     WHERE jaccard_similarity >= %.4f",
    threshold
  )

  pairs <- dbGetQuery(db_connection, pairs_query)

  if (nrow(pairs) == 0) {
    cat("No similar pairs found. Run detect_all_similar_pairs first.\n")
    return(list())
  }

  # Build graph and find connected components
  library(igraph)

  g <- graph_from_data_frame(pairs[, c("doc1_id", "doc2_id")], directed = FALSE)
  components <- components(g)

  # Extract clusters
  clusters <- list()
  for (i in 1:components$no) {
    cluster_docs <- as.integer(names(which(components$membership == i)))

    if (length(cluster_docs) >= min_cluster_size) {
      # Get document metadata
      doc_query <- sprintf(
        "SELECT id, titulo, ano, nivel, esfera, uf
         FROM documents
         WHERE id IN (%s)",
        paste(cluster_docs, collapse = ",")
      )
      cluster_info <- dbGetQuery(db_connection, doc_query)

      clusters[[length(clusters) + 1]] <- list(
        cluster_id = i,
        size = length(cluster_docs),
        documents = cluster_info,
        avg_similarity = mean(pairs$jaccard_similarity[
          pairs$doc1_id %in% cluster_docs & pairs$doc2_id %in% cluster_docs
        ])
      )
    }
  }

  # Sort by cluster size
  clusters <- clusters[order(sapply(clusters, function(x) x$size), decreasing = TRUE)]

  cat(sprintf("Found %d clusters with >= %d documents\n",
              length(clusters), min_cluster_size))

  clusters
}

#' Identify cross-jurisdiction text reuse
#'
#' @param db_connection Database connection
#' @param threshold Numeric, similarity threshold
#' @return Data frame of cross-jurisdiction reuse
#' @export
cross_jurisdiction_reuse <- function(db_connection, threshold = 0.7) {

  query <- sprintf("
    SELECT
      p.doc1_id,
      p.doc2_id,
      p.jaccard_similarity,
      d1.titulo as doc1_titulo,
      d1.nivel as doc1_nivel,
      d1.uf as doc1_uf,
      d1.ano as doc1_ano,
      d2.titulo as doc2_titulo,
      d2.nivel as doc2_nivel,
      d2.uf as doc2_uf,
      d2.ano as doc2_ano
    FROM text_reuse_pairs p
    JOIN documents d1 ON p.doc1_id = d1.id
    JOIN documents d2 ON p.doc2_id = d2.id
    WHERE p.jaccard_similarity >= %.4f
      AND (d1.nivel != d2.nivel OR d1.uf != d2.uf OR (d1.uf IS NULL AND d2.uf IS NOT NULL) OR (d1.uf IS NOT NULL AND d2.uf IS NULL))
    ORDER BY p.jaccard_similarity DESC
  ", threshold)

  result <- dbGetQuery(db_connection, query)

  # Add reuse type classification
  result <- result %>%
    mutate(
      reuse_type = case_when(
        doc1_nivel == "Federal" & doc2_nivel == "Estadual" ~ "Federal→Estadual",
        doc1_nivel == "Estadual" & doc2_nivel == "Federal" ~ "Estadual→Federal",
        doc1_nivel == "Federal" & doc2_nivel == "Municipal" ~ "Federal→Municipal",
        doc1_nivel == "Municipal" & doc2_nivel == "Federal" ~ "Municipal→Federal",
        doc1_nivel == "Estadual" & doc2_nivel == "Municipal" ~ "Estadual→Municipal",
        doc1_nivel == "Municipal" & doc2_nivel == "Estadual" ~ "Municipal→Estadual",
        doc1_nivel == doc2_nivel & doc1_uf != doc2_uf ~ paste0(doc1_nivel, " (", doc1_uf, "→", doc2_uf, ")"),
        TRUE ~ "Other"
      ),
      temporal_direction = case_when(
        doc1_ano < doc2_ano ~ "Earlier→Later",
        doc1_ano > doc2_ano ~ "Later→Earlier",
        TRUE ~ "Same Year"
      )
    )

  result
}

#' Analyze temporal pattern of text reuse for a document
#'
#' @param db_connection Database connection
#' @param focal_doc_id Integer, document ID to analyze
#' @param threshold Numeric, similarity threshold
#' @return Data frame with temporal reuse pattern
#' @export
temporal_reuse_analysis <- function(db_connection,
                                     focal_doc_id,
                                     threshold = 0.7) {

  query <- sprintf("
    SELECT
      CASE
        WHEN p.doc1_id = %d THEN p.doc2_id
        ELSE p.doc1_id
      END as related_doc_id,
      p.jaccard_similarity,
      d.titulo,
      d.ano,
      d.nivel,
      d.uf,
      d.tipo_documento
    FROM text_reuse_pairs p
    JOIN documents d ON (
      CASE
        WHEN p.doc1_id = %d THEN p.doc2_id
        ELSE p.doc1_id
      END = d.id
    )
    WHERE (p.doc1_id = %d OR p.doc2_id = %d)
      AND p.jaccard_similarity >= %.4f
    ORDER BY d.ano, p.jaccard_similarity DESC
  ", focal_doc_id, focal_doc_id, focal_doc_id, focal_doc_id, threshold)

  result <- dbGetQuery(db_connection, query)

  # Get focal document info
  focal_query <- sprintf(
    "SELECT ano, titulo, nivel, uf FROM documents WHERE id = %d",
    focal_doc_id
  )
  focal_info <- dbGetQuery(db_connection, focal_query)

  if (nrow(result) > 0) {
    result <- result %>%
      mutate(
        temporal_relation = case_when(
          ano < focal_info$ano ~ paste0("Predecessor (", focal_info$ano - ano, " years before)"),
          ano > focal_info$ano ~ paste0("Successor (", ano - focal_info$ano, " years after)"),
          TRUE ~ "Same year"
        )
      )
  }

  list(
    focal_document = focal_info,
    related_documents = result,
    total_related = nrow(result),
    avg_similarity = if(nrow(result) > 0) mean(result$jaccard_similarity) else 0
  )
}

#' Get text excerpt showing common content between two documents
#'
#' @param db_connection Database connection
#' @param doc1_id Integer, first document ID
#' @param doc2_id Integer, second document ID
#' @param max_length Integer, maximum excerpt length
#' @return Character, common text excerpt
#' @export
get_common_text_excerpt <- function(db_connection, doc1_id, doc2_id, max_length = 500) {

  # Get both documents
  query <- sprintf(
    "SELECT id, texto_completo FROM documents WHERE id IN (%d, %d)",
    doc1_id, doc2_id
  )
  docs <- dbGetQuery(db_connection, query)

  if (nrow(docs) != 2) {
    return("Documents not found")
  }

  text1 <- docs$texto_completo[docs$id == doc1_id]
  text2 <- docs$texto_completo[docs$id == doc2_id]

  # Create shingles
  shingles1 <- create_shingles(text1, k = 5)
  shingles2 <- create_shingles(text2, k = 5)

  # Find common shingles
  common <- intersect(shingles1, shingles2)

  if (length(common) == 0) {
    return("No common text found")
  }

  # Find longest common shingle in original text
  excerpt <- common[1]
  if (nchar(excerpt) > max_length) {
    excerpt <- substr(excerpt, 1, max_length)
    excerpt <- paste0(excerpt, "...")
  }

  excerpt
}

#' Export LSH index statistics
#'
#' @param db_connection Database connection
#' @return List of statistics
#' @export
lsh_index_stats <- function(db_connection) {

  stats <- list()

  # Total indexed documents
  stats$total_indexed <- dbGetQuery(db_connection,
    "SELECT COUNT(*) as n FROM text_reuse_signatures")$n

  # Total LSH buckets
  stats$total_buckets <- dbGetQuery(db_connection,
    "SELECT COUNT(DISTINCT bucket_hash) as n FROM lsh_buckets")$n

  # Average documents per bucket
  stats$avg_docs_per_bucket <- dbGetQuery(db_connection,
    "SELECT AVG(doc_count) as avg FROM (
       SELECT COUNT(*) as doc_count
       FROM lsh_buckets
       GROUP BY band_number, bucket_hash
     ) sub")$avg

  # Total detected pairs
  stats$total_pairs <- dbGetQuery(db_connection,
    "SELECT COUNT(*) as n FROM text_reuse_pairs")$n

  # Average similarity of detected pairs
  stats$avg_similarity <- dbGetQuery(db_connection,
    "SELECT AVG(jaccard_similarity) as avg FROM text_reuse_pairs")$avg

  # Database size
  stats$db_size_mb <- dbGetQuery(db_connection,
    "SELECT
       pg_size_pretty(pg_total_relation_size('text_reuse_signatures')) as signatures_size,
       pg_size_pretty(pg_total_relation_size('lsh_buckets')) as buckets_size,
       pg_size_pretty(pg_total_relation_size('text_reuse_pairs')) as pairs_size")

  stats
}
