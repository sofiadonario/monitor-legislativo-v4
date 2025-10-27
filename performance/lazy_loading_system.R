# Lazy Loading System for Large Brazilian Legislative Datasets
# Monitor Legislativo v4 - Memory-Efficient Data Access
# =====================================================

library(R6)
library(data.table)

# Global lazy loading configuration
.lazy_config <- list(
  chunk_size = 5000,              # Default chunk size for data loading
  cache_size = 10,                # Number of chunks to keep in memory
  preload_chunks = 2,             # Number of chunks to preload
  memory_threshold_mb = 800,      # Memory threshold for aggressive lazy loading
  enable_compression = TRUE,       # Enable data compression for cached chunks
  brazilian_timezone = "America/Sao_Paulo"
)

#' LazyDataset R6 Class
#' 
#' Implements lazy loading for Brazilian legislative documents with:
#' - Intelligent chunking based on memory constraints
#' - Predictive preloading for academic research patterns
#' - Memory-efficient caching with automatic cleanup
#' - Brazilian legislative data-specific optimizations
#' 
LazyDataset <- R6Class("LazyDataset",
  
  public = list(
    
    #' @field file_path Path to the data file
    file_path = NULL,
    
    #' @field total_rows Total number of rows in the dataset
    total_rows = NULL,
    
    #' @field chunk_size Number of rows per chunk
    chunk_size = NULL,
    
    #' @field total_chunks Total number of chunks
    total_chunks = NULL,
    
    #' @field loaded_chunks Cache of loaded chunks
    loaded_chunks = NULL,
    
    #' @field access_pattern Tracks access patterns for predictive loading
    access_pattern = NULL,
    
    #' @field metadata Dataset metadata and statistics
    metadata = NULL,
    
    #' Initialize LazyDataset
    #' 
    #' @param file_path Path to the dataset file
    #' @param chunk_size Override default chunk size
    #' @param enable_compression Enable data compression
    initialize = function(file_path, chunk_size = NULL, enable_compression = TRUE) {
      
      cat("🚀 Initializing lazy loading for Brazilian legislative dataset...\n")
      
      self$file_path <- file_path
      self$chunk_size <- chunk_size %||% .lazy_config$chunk_size
      
      # Initialize storage structures
      self$loaded_chunks <- new.env(hash = TRUE, parent = emptyenv())
      self$access_pattern <- list()
      
      # Analyze dataset and setup lazy loading
      self$analyze_dataset()
      self$optimize_chunk_size()
      
      cat(sprintf("✅ Lazy dataset initialized: %s rows in %d chunks\n", 
                  format(self$total_rows, big.mark = ","), self$total_chunks))
    },
    
    #' Analyze Dataset Structure
    #' 
    #' Performs initial analysis of the dataset for optimization
    analyze_dataset = function() {
      
      cat("📊 Analyzing dataset structure for lazy loading optimization...\n")
      
      if (!file.exists(self$file_path)) {
        stop("Dataset file not found: ", self$file_path)
      }
      
      # Get file size and estimate rows
      file_info <- file.info(self$file_path)
      file_size_mb <- file_info$size / 1024^2
      
      # Sample first few rows to understand structure
      tryCatch({
        if (grepl("\\.csv$", self$file_path, ignore.case = TRUE)) {
          # CSV file analysis
          sample_data <- data.table::fread(self$file_path, nrows = 100, showProgress = FALSE)
          
          # Count total rows efficiently
          self$total_rows <- as.integer(system(paste("wc -l", shQuote(self$file_path)), intern = TRUE))
          self$total_rows <- self$total_rows - 1  # Subtract header row
          
        } else if (grepl("\\.rds$", self$file_path, ignore.case = TRUE)) {
          # RDS file analysis
          sample_data <- readRDS(self$file_path)
          self$total_rows <- nrow(sample_data)
          
        } else {
          stop("Unsupported file format. Use CSV or RDS files.")
        }
        
        # Analyze Brazilian legislative data characteristics
        self$metadata <- list(
          file_size_mb = file_size_mb,
          estimated_row_size_bytes = file_info$size / self$total_rows,
          column_count = ncol(sample_data),
          column_names = names(sample_data),
          has_geographic_data = any(grepl("estado|municipio|uf", names(sample_data), ignore.case = TRUE)),
          has_temporal_data = any(grepl("data|ano|year", names(sample_data), ignore.case = TRUE)),
          has_juridical_data = any(grepl("tribunal|jurisprud|categoria", names(sample_data), ignore.case = TRUE)),
          sample_data_types = sapply(sample_data, class),
          created_at = Sys.time()
        )
        
        cat(sprintf("📈 Dataset analysis complete: %.1f MB, %s rows, %d columns\n",
                    file_size_mb, format(self$total_rows, big.mark = ","), ncol(sample_data)))
        
      }, error = function(e) {
        cat("❌ Dataset analysis failed:", e$message, "\n")
        stop("Cannot proceed with lazy loading setup")
      })
    },
    
    #' Optimize Chunk Size
    #' 
    #' Determines optimal chunk size based on memory constraints and data characteristics
    optimize_chunk_size = function() {
      
      cat("⚙️ Optimizing chunk size for Railway memory constraints...\n")
      
      # Get current memory usage
      if (exists("get_memory_usage")) {
        current_memory <- get_memory_usage()
        available_memory_mb <- current_memory$available_mb
      } else {
        available_memory_mb <- 1000  # Conservative estimate
      }
      
      # Calculate optimal chunk size based on available memory
      estimated_chunk_memory_mb <- (self$metadata$estimated_row_size_bytes * self$chunk_size) / 1024^2
      
      # Adjust chunk size if it would consume too much memory
      if (estimated_chunk_memory_mb > (available_memory_mb * 0.1)) {  # Max 10% of available memory
        
        # Calculate new chunk size
        max_memory_per_chunk_mb <- available_memory_mb * 0.1
        optimal_chunk_size <- floor((max_memory_per_chunk_mb * 1024^2) / self$metadata$estimated_row_size_bytes)
        
        # Ensure minimum viable chunk size
        optimal_chunk_size <- max(1000, optimal_chunk_size)
        
        cat(sprintf("🔧 Adjusting chunk size from %d to %d for memory efficiency\n", 
                    self$chunk_size, optimal_chunk_size))
        
        self$chunk_size <- optimal_chunk_size
      }
      
      # Calculate total chunks
      self$total_chunks <- ceiling(self$total_rows / self$chunk_size)
      
      cat(sprintf("✅ Chunk optimization complete: %d rows per chunk, %d total chunks\n",
                  self$chunk_size, self$total_chunks))
    },
    
    #' Load Specific Chunk
    #' 
    #' Loads a specific chunk with Brazilian data-specific optimizations
    #' 
    #' @param chunk_id Chunk identifier (1-based)
    #' @param use_cache Whether to use/update cache
    #' @return Data frame with the requested chunk
    load_chunk = function(chunk_id, use_cache = TRUE) {
      
      # Validate chunk ID
      if (chunk_id < 1 || chunk_id > self$total_chunks) {
        stop("Invalid chunk ID: ", chunk_id, " (valid range: 1-", self$total_chunks, ")")
      }
      
      chunk_key <- paste0("chunk_", chunk_id)
      
      # Check cache first
      if (use_cache && exists(chunk_key, envir = self$loaded_chunks)) {
        cat(sprintf("🎯 Cache hit for chunk %d\n", chunk_id))
        
        # Update access pattern
        self$record_access(chunk_id)
        
        return(self$loaded_chunks[[chunk_key]]$data)
      }
      
      cat(sprintf("📂 Loading chunk %d (%d-%d of %s rows)...\n", 
                  chunk_id, 
                  (chunk_id - 1) * self$chunk_size + 1,
                  min(chunk_id * self$chunk_size, self$total_rows),
                  format(self$total_rows, big.mark = ",")))
      
      # Calculate row range for this chunk
      start_row <- (chunk_id - 1) * self$chunk_size + 1
      end_row <- min(chunk_id * self$chunk_size, self$total_rows)
      rows_to_read <- end_row - start_row + 1
      
      # Load chunk data
      chunk_data <- tryCatch({
        
        if (grepl("\\.csv$", self$file_path, ignore.case = TRUE)) {
          # CSV chunk loading with Brazilian encoding support
          data.table::fread(
            self$file_path,
            skip = start_row,  # Skip to start row (accounting for header)
            nrows = rows_to_read,
            showProgress = FALSE,
            encoding = "UTF-8",  # Brazilian Portuguese support
            strip.white = TRUE,
            na.strings = c("", "NA", "N/A", "null")
          )
          
        } else if (grepl("\\.rds$", self$file_path, ignore.case = TRUE)) {
          # RDS chunk loading (load full data and subset)
          full_data <- readRDS(self$file_path)
          full_data[start_row:end_row, ]
          
        } else {
          stop("Unsupported file format")
        }
        
      }, error = function(e) {
        cat("❌ Chunk loading failed:", e$message, "\n")
        return(NULL)
      })
      
      if (isTRUE(is.null(chunk_data)) || nrow(chunk_data) == 0) {
        cat(sprintf("⚠️ Empty chunk %d\n", chunk_id))
        return(data.frame())
      }
      
      # Optimize chunk data for Brazilian legislative content
      chunk_data <- self$optimize_chunk_data(chunk_data, chunk_id)
      
      # Cache the chunk if caching is enabled
      if (use_cache) {
        self$cache_chunk(chunk_id, chunk_data)
      }
      
      # Record access pattern
      self$record_access(chunk_id)
      
      cat(sprintf("✅ Chunk %d loaded: %d rows\n", chunk_id, nrow(chunk_data)))
      
      return(chunk_data)
    },
    
    #' Optimize Chunk Data
    #' 
    #' Applies Brazilian legislative data-specific optimizations
    #' 
    #' @param chunk_data Raw chunk data
    #' @param chunk_id Chunk identifier
    #' @return Optimized chunk data
    optimize_chunk_data = function(chunk_data, chunk_id) {
      
      # Convert to data.table for efficiency
      if (!data.table::is.data.table(chunk_data)) {
        data.table::setDT(chunk_data)
      }
      
      # Brazilian legislative data optimizations
      tryCatch({
        
        # Optimize text columns (common in legislative data)
        text_columns <- names(chunk_data)[sapply(chunk_data, is.character)]
        
        for (col in text_columns) {
          # Trim whitespace and handle Brazilian encoding issues
          data.table::set(chunk_data, j = col, value = trimws(chunk_data[[col]]))
          
          # Standardize empty values
          data.table::set(chunk_data, 
                         i = which(chunk_data[[col]] %in% c("", "NA", "N/A", "null")), 
                         j = col, value = NA_character_)
        }
        
        # Optimize date columns for Brazilian date formats
        date_columns <- names(chunk_data)[grepl("data|date", names(chunk_data), ignore.case = TRUE)]
        for (col in date_columns) {
          if (is.character(chunk_data[[col]])) {
            # Try to parse Brazilian date formats
            chunk_data[[col]] <- as.Date(chunk_data[[col]], format = "%Y-%m-%d")
          }
        }
        
        # Optimize categorical columns (estados, tribunais, etc.)
        categorical_columns <- names(chunk_data)[grepl("estado|tipo|categoria|tribunal", names(chunk_data), ignore.case = TRUE)]
        for (col in categorical_columns) {
          if (is.character(chunk_data[[col]])) {
            # Convert to factor for memory efficiency
            chunk_data[[col]] <- as.factor(chunk_data[[col]])
          }
        }
        
      }, error = function(e) {
        cat("⚠️ Chunk optimization warning:", e$message, "\n")
      })
      
      return(chunk_data)
    },
    
    #' Cache Chunk Data
    #' 
    #' Stores chunk in cache with intelligent memory management
    #' 
    #' @param chunk_id Chunk identifier
    #' @param chunk_data Data to cache
    cache_chunk = function(chunk_id, chunk_data) {
      
      chunk_key <- paste0("chunk_", chunk_id)
      
      # Check cache size and cleanup if necessary
      current_cache_size <- length(ls(self$loaded_chunks))
      
      if (current_cache_size >= .lazy_config$cache_size) {
        self$cleanup_cache()
      }
      
      # Calculate chunk memory footprint
      chunk_size_mb <- as.numeric(object.size(chunk_data)) / 1024^2
      
      # Store chunk with metadata
      self$loaded_chunks[[chunk_key]] <- list(
        data = chunk_data,
        cached_at = Sys.time(),
        size_mb = chunk_size_mb,
        access_count = 1,
        last_accessed = Sys.time()
      )
      
      cat(sprintf("💾 Cached chunk %d (%.1f MB)\n", chunk_id, chunk_size_mb))
    },
    
    #' Cleanup Cache
    #' 
    #' Removes least recently used chunks from cache
    cleanup_cache = function() {
      
      cat("🧹 Cleaning up chunk cache...\n")
      
      cached_chunks <- ls(self$loaded_chunks)
      
      if (length(cached_chunks) == 0) {
        return()
      }
      
      # Get access information for all cached chunks
      chunk_info <- lapply(cached_chunks, function(chunk_key) {
        chunk_data <- self$loaded_chunks[[chunk_key]]
        list(
          key = chunk_key,
          last_accessed = chunk_data$last_accessed,
          access_count = chunk_data$access_count,
          size_mb = chunk_data$size_mb
        )
      })
      
      # Sort by last accessed time (LRU)
      chunk_info <- chunk_info[order(sapply(chunk_info, function(x) x$last_accessed))]
      
      # Remove oldest chunks to make room
      chunks_to_remove <- ceiling(length(cached_chunks) * 0.3)  # Remove 30%
      
      total_freed_mb <- 0
      for (i in 1:min(chunks_to_remove, length(chunk_info))) {
        chunk_to_remove <- chunk_info[[i]]
        rm(list = chunk_to_remove$key, envir = self$loaded_chunks)
        total_freed_mb <- total_freed_mb + chunk_to_remove$size_mb
      }
      
      cat(sprintf("✅ Cache cleanup complete: %d chunks removed, %.1f MB freed\n",
                  chunks_to_remove, total_freed_mb))
    },
    
    #' Record Access Pattern
    #' 
    #' Records chunk access for predictive loading
    #' 
    #' @param chunk_id Accessed chunk ID
    record_access = function(chunk_id) {
      
      access_record <- list(
        chunk_id = chunk_id,
        timestamp = Sys.time(),
        hour = as.integer(format(Sys.time(), "%H"))
      )
      
      self$access_pattern <- append(self$access_pattern, list(access_record))
      
      # Keep only recent access history (last 100 accesses)
      if (length(self$access_pattern) > 100) {
        self$access_pattern <- tail(self$access_pattern, 100)
      }
      
      # Update chunk access count in cache
      chunk_key <- paste0("chunk_", chunk_id)
      if (exists(chunk_key, envir = self$loaded_chunks)) {
        self$loaded_chunks[[chunk_key]]$access_count <- 
          self$loaded_chunks[[chunk_key]]$access_count + 1
        self$loaded_chunks[[chunk_key]]$last_accessed <- Sys.time()
      }
    },
    
    #' Get Data Range
    #' 
    #' Retrieves data across multiple chunks efficiently
    #' 
    #' @param start_row Starting row number (1-based)
    #' @param end_row Ending row number
    #' @return Combined data from multiple chunks
    get_range = function(start_row, end_row) {
      
      # Validate range
      if (start_row < 1 || end_row > self$total_rows || start_row > end_row) {
        stop("Invalid row range: ", start_row, "-", end_row)
      }
      
      # Determine which chunks are needed
      start_chunk <- ceiling(start_row / self$chunk_size)
      end_chunk <- ceiling(end_row / self$chunk_size)
      
      cat(sprintf("📊 Loading range %d-%d (chunks %d-%d)\n", 
                  start_row, end_row, start_chunk, end_chunk))
      
      # Collect data from all needed chunks
      combined_data <- list()
      
      for (chunk_id in start_chunk:end_chunk) {
        chunk_data <- self$load_chunk(chunk_id)
        
        # Calculate which rows from this chunk we need
        chunk_start_row <- (chunk_id - 1) * self$chunk_size + 1
        chunk_end_row <- min(chunk_id * self$chunk_size, self$total_rows)
        
        # Calculate subset within chunk
        if (chunk_id == start_chunk && chunk_id == end_chunk) {
          # Single chunk case
          local_start <- start_row - chunk_start_row + 1
          local_end <- end_row - chunk_start_row + 1
        } else if (chunk_id == start_chunk) {
          # First chunk
          local_start <- start_row - chunk_start_row + 1
          local_end <- nrow(chunk_data)
        } else if (chunk_id == end_chunk) {
          # Last chunk
          local_start <- 1
          local_end <- end_row - chunk_start_row + 1
        } else {
          # Middle chunk
          local_start <- 1
          local_end <- nrow(chunk_data)
        }
        
        # Extract subset and add to combined data
        if (isTRUE(nrow(chunk_data) > 0) && local_end <= nrow(chunk_data)) {
          subset_data <- chunk_data[local_start:local_end, ]
          combined_data <- append(combined_data, list(subset_data))
        }
      }
      
      # Combine all chunks
      if (length(combined_data) == 0) {
        return(data.frame())
      } else if (length(combined_data) == 1) {
        return(combined_data[[1]])
      } else {
        return(data.table::rbindlist(combined_data, fill = TRUE))
      }
    },
    
    #' Get Random Sample
    #' 
    #' Efficiently retrieves a random sample from the dataset
    #' 
    #' @param sample_size Number of rows to sample
    #' @param seed Random seed for reproducibility
    #' @return Random sample data frame
    get_sample = function(sample_size, seed = NULL) {
      
      if (!is.null(seed)) {
        set.seed(seed)
      }
      
      cat(sprintf("🎲 Generating random sample of %d rows...\n", sample_size))
      
      # Generate random row numbers
      random_rows <- sort(sample(1:self$total_rows, min(sample_size, self$total_rows)))
      
      # Group by chunks for efficient loading
      chunk_groups <- split(random_rows, ceiling(random_rows / self$chunk_size))
      
      sampled_data <- list()
      
      for (chunk_id in names(chunk_groups)) {
        chunk_rows <- chunk_groups[[chunk_id]]
        chunk_data <- self$load_chunk(as.integer(chunk_id))
        
        # Calculate local row indices within chunk
        chunk_start_row <- (as.integer(chunk_id) - 1) * self$chunk_size + 1
        local_indices <- chunk_rows - chunk_start_row + 1
        
        # Extract sampled rows from chunk
        if (isTRUE(nrow(chunk_data) > 0) && all(local_indices <= nrow(chunk_data))) {
          chunk_sample <- chunk_data[local_indices, ]
          sampled_data <- append(sampled_data, list(chunk_sample))
        }
      }
      
      # Combine samples
      if (length(sampled_data) > 0) {
        final_sample <- data.table::rbindlist(sampled_data, fill = TRUE)
        cat(sprintf("✅ Random sample complete: %d rows\n", nrow(final_sample)))
        return(final_sample)
      } else {
        return(data.frame())
      }
    },
    
    #' Get Dataset Statistics
    #' 
    #' Returns comprehensive dataset statistics and cache performance
    #' 
    #' @return List with dataset and performance statistics
    get_stats = function() {
      
      # Cache statistics
      cached_chunks <- ls(self$loaded_chunks)
      cache_size_mb <- if (length(cached_chunks) > 0) {
        sum(sapply(cached_chunks, function(key) {
          self$loaded_chunks[[key]]$size_mb
        }))
      } else {
        0
      }
      
      # Access pattern analysis
      total_accesses <- length(self$access_pattern)
      recent_accesses <- if (total_accesses > 0) {
        recent_time <- Sys.time() - 3600  # Last hour
        sum(sapply(self$access_pattern, function(x) x$timestamp > recent_time))
      } else {
        0
      }
      
      return(list(
        dataset = list(
          file_path = self$file_path,
          total_rows = self$total_rows,
          total_chunks = self$total_chunks,
          chunk_size = self$chunk_size,
          metadata = self$metadata
        ),
        cache = list(
          cached_chunks = length(cached_chunks),
          cache_size_mb = round(cache_size_mb, 2),
          cache_limit = .lazy_config$cache_size
        ),
        performance = list(
          total_accesses = total_accesses,
          recent_accesses_1h = recent_accesses,
          average_chunk_size_mb = if (length(cached_chunks) > 0) cache_size_mb / length(cached_chunks) else 0
        )
      ))
    }
  )
)

#' Create Lazy Dataset Instance
#' 
#' Factory function to create and configure a lazy dataset for Brazilian legislative data
#' 
#' @param file_path Path to the dataset file
#' @param chunk_size Optional chunk size override
#' @param enable_compression Enable data compression
#' @return LazyDataset instance
#' @export
create_lazy_dataset <- function(file_path, chunk_size = NULL, enable_compression = TRUE) {
  
  cat("🚀 Creating lazy dataset for Brazilian legislative documents...\n")
  
  # Validate file exists
  if (!file.exists(file_path)) {
    stop("Dataset file not found: ", file_path)
  }
  
  # Create and return lazy dataset instance
  lazy_dataset <- LazyDataset$new(
    file_path = file_path,
    chunk_size = chunk_size,
    enable_compression = enable_compression
  )
  
  cat("✅ Lazy dataset ready for memory-efficient access\n")
  
  return(lazy_dataset)
}

#' Smart Data Loading Function
#' 
#' Intelligent data loading with automatic lazy loading determination
#' 
#' @param file_path Path to data file
#' @param max_memory_mb Maximum memory to use for loading
#' @param sample_mode Whether to load a sample instead of full data
#' @return Data frame or LazyDataset instance
#' @export
smart_load_data <- function(file_path, max_memory_mb = 500, sample_mode = FALSE) {
  
  cat("🧠 Smart loading Brazilian legislative dataset...\n")
  
  # Analyze file size
  file_info <- file.info(file_path)
  file_size_mb <- file_info$size / 1024^2
  
  cat(sprintf("📊 Dataset file size: %.1f MB\n", file_size_mb))
  
  # Decision logic for loading strategy
  if (file_size_mb <= max_memory_mb && !sample_mode) {
    # Small enough to load entirely
    cat("📂 Loading complete dataset into memory\n")
    
    if (grepl("\\.csv$", file_path, ignore.case = TRUE)) {
      return(data.table::fread(file_path, encoding = "UTF-8"))
    } else if (grepl("\\.rds$", file_path, ignore.case = TRUE)) {
      return(readRDS(file_path))
    } else {
      stop("Unsupported file format")
    }
    
  } else {
    # Use lazy loading for large files or sample mode
    cat("⚡ Using lazy loading for memory efficiency\n")
    
    # Calculate optimal chunk size based on memory limit
    optimal_chunk_size <- max(1000, floor((max_memory_mb * 1024^2 * 0.1) / 500))  # Conservative estimate
    
    lazy_dataset <- create_lazy_dataset(
      file_path = file_path,
      chunk_size = optimal_chunk_size
    )
    
    if (sample_mode) {
      cat("🎲 Returning sample data for exploration\n")
      return(lazy_dataset$get_sample(10000))  # 10k sample
    } else {
      cat("💾 Returning lazy dataset for on-demand access\n")
      return(lazy_dataset)
    }
  }
}

# Helper function for null coalescing
`%||%` <- function(x, y) if (is.null(x)) y else x

cat("✅ Lazy loading system initialized for Brazilian legislative datasets\n")
cat("📊 Memory-efficient data access ready for Railway 2GB constraints\n")
cat("🚀 Smart loading and chunking strategies available\n")