# Memory-Efficient CSV Loading Module
# ====================================
# This module provides memory-efficient loading of large CSV files
# with chunking, sampling, and garbage collection for Railway deployment

library(data.table)

# Railway memory constraints
RAILWAY_MEMORY_LIMIT <- as.numeric(Sys.getenv("R_MAX_MEM_SIZE", "2000"))  # MB
CHUNK_SIZE <- 50000  # Rows per chunk
SAMPLE_SIZE <- 200000  # Max rows for sampling mode

# Function to estimate memory usage for a CSV file
estimate_csv_memory <- function(csv_path, sample_rows = 1000) {
  if (!file.exists(csv_path)) {
    warning("File does not exist: ", csv_path)
    return(list(estimated_memory_mb = 0, total_rows = 0))
  }

  tryCatch({
    # Read sample to estimate memory per row
    sample_data <- data.table::fread(
      csv_path,
      nrows = sample_rows,
      showProgress = FALSE,
      verbose = FALSE
    )

    # Get row count efficiently
    total_rows <- as.numeric(system2("wc",
                                      args = c("-l", shQuote(csv_path)),
                                      stdout = TRUE))
    total_rows <- as.numeric(gsub("\\s.*", "", total_rows)) - 1  # Subtract header

    # Estimate memory usage
    memory_per_row <- as.numeric(object.size(sample_data)) / nrow(sample_data)
    estimated_memory_mb <- (memory_per_row * total_rows) / (1024^2)

    rm(sample_data)
    gc()

    return(list(
      estimated_memory_mb = round(estimated_memory_mb, 1),
      total_rows = total_rows,
      memory_per_row = memory_per_row
    ))
  }, error = function(e) {
    # Fallback to file size estimation
    file_size_mb <- file.size(csv_path) / (1024^2)
    return(list(
      estimated_memory_mb = file_size_mb * 2,  # Rough estimate: 2x file size
      total_rows = NA
    ))
  })
}

# Main memory-efficient loading function
load_csv_memory_efficient <- function(csv_path,
                                      max_rows = NULL,
                                      columns = NULL,
                                      use_sampling = TRUE,
                                      chunk_processing = FALSE,
                                      progress_callback = NULL) {

  cat("\n🔄 Memory-efficient CSV loading initiated\n")
  cat("📁 File:", csv_path, "\n")

  # Check current memory usage
  current_mem <- as.numeric(gc()[2, 2])  # Current memory in MB
  available_mem <- RAILWAY_MEMORY_LIMIT - current_mem
  cat("💾 Available memory:", round(available_mem, 1), "MB\n")

  # Estimate memory requirements
  mem_estimate <- estimate_csv_memory(csv_path)
  cat("📊 Estimated data size:", mem_estimate$estimated_memory_mb, "MB\n")
  cat("📑 Total rows:", format(mem_estimate$total_rows, big.mark = ","), "\n")

  # Determine loading strategy
  if (chunk_processing) {
    cat("⚡ Using chunked processing strategy\n")
    return(load_csv_in_chunks(csv_path, columns, max_rows, progress_callback))
  }

  if (mem_estimate$estimated_memory_mb > available_mem * 0.8) {
    cat("⚠️ File too large for available memory\n")

    if (use_sampling) {
      cat("📈 Using intelligent sampling strategy\n")
      return(load_csv_with_sampling(csv_path, columns, max_rows))
    } else {
      cat("🔄 Falling back to chunked processing\n")
      return(load_csv_in_chunks(csv_path, columns, max_rows, progress_callback))
    }
  }

  # Direct loading for smaller files
  cat("✅ Loading full file (within memory limits)\n")
  return(load_csv_direct(csv_path, columns, max_rows))
}

# Direct loading for smaller files
load_csv_direct <- function(csv_path, columns = NULL, max_rows = NULL) {
  tryCatch({
    # Prepare fread arguments
    fread_args <- list(
      file = csv_path,
      encoding = "UTF-8",
      showProgress = TRUE,
      data.table = FALSE
    )

    if (!is.null(columns)) {
      fread_args$select <- columns
    }

    if (!is.null(max_rows)) {
      fread_args$nrows <- max_rows
    }

    # Load data
    data <- do.call(data.table::fread, fread_args)

    cat("✅ Loaded", nrow(data), "rows with", ncol(data), "columns\n")

    # Force garbage collection
    gc()

    return(data)
  }, error = function(e) {
    warning("Error loading CSV directly: ", e$message)
    return(NULL)
  })
}

# Sampling-based loading for large files
load_csv_with_sampling <- function(csv_path, columns = NULL, max_rows = NULL) {
  tryCatch({
    # Determine sample size
    sample_size <- min(SAMPLE_SIZE, max_rows %||% SAMPLE_SIZE)

    cat("📊 Loading sample of", format(sample_size, big.mark = ","), "rows\n")

    # Get total rows for stratified sampling
    total_rows <- as.numeric(system2("wc",
                                      args = c("-l", shQuote(csv_path)),
                                      stdout = TRUE))
    total_rows <- as.numeric(gsub("\\s.*", "", total_rows)) - 1

    if (sample_size >= total_rows) {
      # Load all if sample size exceeds total
      return(load_csv_direct(csv_path, columns, max_rows))
    }

    # Calculate sampling rate
    sampling_rate <- sample_size / total_rows
    cat("📈 Sampling rate:", round(sampling_rate * 100, 1), "%\n")

    # Load with sampling
    if (sampling_rate < 0.5) {
      # For low sampling rates, read specific rows
      skip_interval <- floor(1 / sampling_rate)

      # Create row indices to read
      row_indices <- seq(1, total_rows, by = skip_interval)[1:sample_size]

      # Read header first
      header <- data.table::fread(csv_path, nrows = 0)
      col_names <- names(header)

      if (!is.null(columns)) {
        col_indices <- which(col_names %in% columns)
      } else {
        col_indices <- seq_along(col_names)
      }

      # Read sampled rows in chunks
      sampled_data <- list()
      chunk_size <- 10000

      for (i in seq(1, length(row_indices), by = chunk_size)) {
        chunk_indices <- row_indices[i:min(i + chunk_size - 1, length(row_indices))]

        # Read chunk using system command for efficiency
        cmd <- sprintf("sed -n '%s' '%s'",
                       paste(chunk_indices, "p", sep = "", collapse = ";"),
                       csv_path)

        chunk_text <- system(cmd, intern = TRUE)

        if (length(chunk_text) > 0) {
          chunk_data <- data.table::fread(
            text = chunk_text,
            header = FALSE,
            col.names = col_names[col_indices]
          )
          sampled_data[[length(sampled_data) + 1]] <- chunk_data
        }

        # Progress update
        if (!is.null(progress_callback)) {
          progress_callback(
            current = min(i + chunk_size, length(row_indices)),
            total = length(row_indices),
            message = "Sampling rows"
          )
        }
      }

      # Combine sampled chunks
      result <- data.table::rbindlist(sampled_data, use.names = TRUE)

    } else {
      # For high sampling rates, read full file and sample
      full_data <- load_csv_direct(csv_path, columns)

      if (!is.null(full_data)) {
        sample_indices <- sample(nrow(full_data), sample_size)
        result <- full_data[sample_indices, ]
        rm(full_data)
      } else {
        return(NULL)
      }
    }

    cat("✅ Sampled", nrow(result), "rows\n")

    # Add sampling metadata
    attr(result, "sampling_info") <- list(
      total_rows = total_rows,
      sample_size = nrow(result),
      sampling_rate = sampling_rate,
      method = if(sampling_rate < 0.5) "systematic" else "random"
    )

    gc()
    return(result)

  }, error = function(e) {
    warning("Error in sampling-based loading: ", e$message)
    return(NULL)
  })
}

# Chunked processing for very large files
load_csv_in_chunks <- function(csv_path, columns = NULL, max_rows = NULL, progress_callback = NULL) {
  cat("🔄 Starting chunked CSV processing\n")

  tryCatch({
    # Get total rows
    total_rows <- as.numeric(system2("wc",
                                      args = c("-l", shQuote(csv_path)),
                                      stdout = TRUE))
    total_rows <- as.numeric(gsub("\\s.*", "", total_rows)) - 1

    if (!is.null(max_rows)) {
      total_rows <- min(total_rows, max_rows)
    }

    # Calculate number of chunks
    num_chunks <- ceiling(total_rows / CHUNK_SIZE)
    cat("📦 Processing", format(total_rows, big.mark = ","),
        "rows in", num_chunks, "chunks\n")

    # Process chunks
    all_chunks <- list()
    rows_processed <- 0

    for (chunk_num in 1:num_chunks) {
      # Check memory before loading chunk
      current_mem <- as.numeric(gc()[2, 2])
      if (current_mem > RAILWAY_MEMORY_LIMIT * 0.9) {
        warning("Memory limit approaching, stopping at chunk ", chunk_num)
        break
      }

      # Calculate chunk parameters
      skip_rows <- (chunk_num - 1) * CHUNK_SIZE
      chunk_rows <- min(CHUNK_SIZE, total_rows - skip_rows)

      # Read chunk
      chunk_data <- data.table::fread(
        csv_path,
        skip = skip_rows,
        nrows = chunk_rows,
        select = columns,
        encoding = "UTF-8",
        showProgress = FALSE,
        data.table = FALSE
      )

      all_chunks[[chunk_num]] <- chunk_data
      rows_processed <- rows_processed + nrow(chunk_data)

      # Progress callback
      if (!is.null(progress_callback)) {
        progress_callback(
          chunk = chunk_num,
          total_chunks = num_chunks,
          rows_processed = rows_processed,
          total_rows = total_rows,
          percentage = round((rows_processed / total_rows) * 100, 1)
        )
      }

      # Periodic garbage collection
      if (chunk_num %% 5 == 0) {
        gc()
      }

      # Stop if we've reached max_rows
      if (!is.null(max_rows) && rows_processed >= max_rows) {
        break
      }
    }

    # Combine chunks efficiently
    cat("🔗 Combining", length(all_chunks), "chunks\n")
    result <- data.table::rbindlist(all_chunks, use.names = TRUE, fill = TRUE)

    cat("✅ Loaded", nrow(result), "rows via chunked processing\n")

    # Clean up
    rm(all_chunks)
    gc()

    return(as.data.frame(result))

  }, error = function(e) {
    warning("Error in chunked loading: ", e$message)
    return(NULL)
  })
}

# Helper function for NULL coalescing
`%||%` <- function(a, b) if (is.null(a)) b else a

# Automatic memory monitoring and cleanup
monitor_memory_usage <- function() {
  current_mem <- as.numeric(gc()[2, 2])
  mem_percentage <- (current_mem / RAILWAY_MEMORY_LIMIT) * 100

  status <- list(
    current_mb = round(current_mem, 1),
    limit_mb = RAILWAY_MEMORY_LIMIT,
    percentage = round(mem_percentage, 1),
    status = if (mem_percentage > 90) "CRITICAL"
             else if (mem_percentage > 75) "WARNING"
             else "OK"
  )

  if (status$status == "CRITICAL") {
    cat("🚨 CRITICAL: Memory usage at", status$percentage, "%\n")
    cat("🔄 Forcing garbage collection\n")
    gc()

    # Re-check after GC
    current_mem <- as.numeric(gc()[2, 2])
    status$current_mb <- round(current_mem, 1)
    status$percentage <- round((current_mem / RAILWAY_MEMORY_LIMIT) * 100, 1)
  }

  return(status)
}

# Export main function
list(
  load_csv_memory_efficient = load_csv_memory_efficient,
  estimate_csv_memory = estimate_csv_memory,
  monitor_memory_usage = monitor_memory_usage
)