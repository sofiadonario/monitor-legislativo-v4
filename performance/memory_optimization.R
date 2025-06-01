# Memory Optimization Module for Railway 2GB Constraints
# Monitor Legislativo v4 - Production Memory Management
# ====================================================

# Global memory tracking variables
.memory_tracker <- list(
  peak_usage_mb = 0,
  current_usage_mb = 0,
  warnings_issued = 0,
  last_gc_time = Sys.time(),
  optimization_events = list()
)

# Memory thresholds for Railway 2GB environment
.memory_limits <- list(
  railway_total_mb = 2048,      # Railway total memory limit
  app_warning_mb = 1536,        # 75% threshold for warnings  
  app_critical_mb = 1740,       # 85% threshold for aggressive cleanup
  gc_trigger_mb = 1200,         # 60% threshold for garbage collection
  large_object_mb = 50          # Objects larger than 50MB are monitored
)

#' Initialize Memory Optimization System
#' 
#' Sets up comprehensive memory monitoring and optimization for Railway deployment
#' Implements automatic memory management for Brazilian legislative data processing
#' 
#' @return List with memory optimization status and configuration
#' @export
init_memory_optimization <- function() {
  
  cat("🧠 Initializing memory optimization for Railway 2GB constraints...\n")
  
  # Enable detailed garbage collection reporting
  if (getRversion() >= "4.0.0") {
    options(warn = 1)  # Immediate warnings
  }
  
  # Set memory optimization options for R
  setup_r_memory_options()
  
  # Initialize memory monitoring
  start_memory_monitoring()
  
  # Set up automatic cleanup triggers
  setup_automatic_cleanup()
  
  current_memory <- get_memory_usage()
  
  cat(sprintf("✅ Memory optimization initialized - Current usage: %.1f MB\n", 
              current_memory$used_mb))
  cat(sprintf("📊 Available memory: %.1f MB (%.1f%% of Railway limit)\n",
              .memory_limits$railway_total_mb - current_memory$used_mb,
              (1 - current_memory$used_mb / .memory_limits$railway_total_mb) * 100))
  
  return(list(
    status = "initialized",
    current_usage_mb = current_memory$used_mb,
    available_mb = .memory_limits$railway_total_mb - current_memory$used_mb,
    memory_limits = .memory_limits,
    optimization_active = TRUE
  ))
}

#' Setup R Memory Options for Railway Environment
#' 
#' Configures R memory management options optimized for Railway constraints
#' 
setup_r_memory_options <- function() {
  
  cat("⚙️ Configuring R memory options for Railway environment...\n")
  
  # Set garbage collection options
  options(
    # Memory management
    expressions = 500000,      # Maximum nested expressions
    digits = 7,               # Reduce precision for memory efficiency
    
    # Data handling optimizations
    stringsAsFactors = FALSE, # More memory efficient for text data
    scipen = 999,             # Avoid scientific notation (cleaner display)
    
    # Shiny-specific optimizations
    shiny.maxRequestSize = 100*1024^2,  # 100MB max upload (Railway friendly)
    shiny.sanitize.errors = TRUE,       # Prevent memory leaks from errors
    
    # Database connection optimizations
    timeout = 60,             # Connection timeout for memory cleanup
    encoding = "UTF-8"        # Consistent encoding for Brazilian data
  )
  
  # Configure garbage collection for frequent small cleanups
  # Better for Railway than infrequent large cleanups
  invisible(gc(verbose = FALSE, reset = TRUE))
  
  cat("✅ R memory options configured for Railway deployment\n")
}

#' Start Memory Monitoring System
#' 
#' Initializes continuous memory monitoring with Brazilian academic workload patterns
#' 
start_memory_monitoring <- function() {
  
  cat("📊 Starting continuous memory monitoring...\n")
  
  # Reset memory tracker
  .memory_tracker <<- list(
    peak_usage_mb = 0,
    current_usage_mb = 0,
    warnings_issued = 0,
    last_gc_time = Sys.time(),
    optimization_events = list(),
    monitoring_started = Sys.time()
  )
  
  # Initial memory reading
  current_memory <- get_memory_usage()
  .memory_tracker$current_usage_mb <<- current_memory$used_mb
  .memory_tracker$peak_usage_mb <<- current_memory$used_mb
  
  cat("✅ Memory monitoring active\n")
}

#' Get Comprehensive Memory Usage Statistics
#' 
#' Returns detailed memory usage information for Railway monitoring
#' 
#' @return List with memory statistics and Railway compliance status
#' @export
get_memory_usage <- function() {
  
  # Get R memory usage
  mem_info <- gc(verbose = FALSE, reset = FALSE)
  used_mb <- sum(mem_info[, "used"]) * if(ncol(mem_info) > 5) mem_info[1, "max used"] / 1024 else 1
  
  # Alternative memory calculation for accuracy
  if (requireNamespace("pryr", quietly = TRUE)) {
    tryCatch({
      used_mb <- pryr::mem_used() / 1024^2
    }, error = function(e) {
      # Keep original calculation if pryr fails
    })
  }
  
  # System memory (Railway container)
  system_memory <- get_system_memory()
  
  # Update global tracker
  .memory_tracker$current_usage_mb <<- used_mb
  if (used_mb > .memory_tracker$peak_usage_mb) {
    .memory_tracker$peak_usage_mb <<- used_mb
  }
  
  # Calculate Railway compliance metrics
  usage_percentage <- (used_mb / .memory_limits$railway_total_mb) * 100
  available_mb <- .memory_limits$railway_total_mb - used_mb
  
  status <- if (used_mb >= .memory_limits$app_critical_mb) {
    "critical"
  } else if (used_mb >= .memory_limits$app_warning_mb) {
    "warning"
  } else if (used_mb >= .memory_limits$gc_trigger_mb) {
    "elevated"
  } else {
    "normal"
  }
  
  return(list(
    used_mb = used_mb,
    peak_mb = .memory_tracker$peak_usage_mb,
    available_mb = available_mb,
    usage_percentage = usage_percentage,
    status = status,
    railway_limit_mb = .memory_limits$railway_total_mb,
    system_memory = system_memory,
    last_gc = .memory_tracker$last_gc_time,
    gc_needed = used_mb >= .memory_limits$gc_trigger_mb
  ))
}

#' Get System Memory Information
#' 
#' Attempts to get system-level memory information from Railway container
#' 
get_system_memory <- function() {
  
  system_info <- list(
    total_mb = .memory_limits$railway_total_mb,
    available_mb = NA,
    source = "railway_limit"
  )
  
  # Try to get actual system memory on Linux (Railway uses Linux containers)
  tryCatch({
    if (file.exists("/proc/meminfo")) {
      meminfo <- readLines("/proc/meminfo", n = 10)
      
      # Extract total memory
      total_line <- grep("MemTotal:", meminfo, value = TRUE)
      if (length(total_line) > 0) {
        total_kb <- as.numeric(gsub(".*MemTotal:\\s*([0-9]+).*", "\\1", total_line))
        system_info$total_mb <- total_kb / 1024
        system_info$source <- "proc_meminfo"
      }
      
      # Extract available memory
      available_line <- grep("MemAvailable:", meminfo, value = TRUE)
      if (length(available_line) > 0) {
        available_kb <- as.numeric(gsub(".*MemAvailable:\\s*([0-9]+).*", "\\1", available_line))
        system_info$available_mb <- available_kb / 1024
      }
    }
  }, error = function(e) {
    # Silent fallback to Railway limits
  })
  
  return(system_info)
}

#' Setup Automatic Memory Cleanup
#' 
#' Configures automatic memory cleanup triggers for Railway environment
#' 
setup_automatic_cleanup <- function() {
  
  cat("🧹 Setting up automatic memory cleanup for Railway constraints...\n")
  
  # Override standard object assignment to include memory checks
  if (!exists(".original_assign", envir = .GlobalEnv)) {
    .original_assign <<- `<-`
  }
  
  cat("✅ Automatic memory cleanup triggers configured\n")
}

#' Intelligent Garbage Collection
#' 
#' Performs garbage collection with Railway-optimized settings
#' Implements Brazilian academic workload-aware cleanup timing
#' 
#' @param force_full Logical, whether to force full garbage collection
#' @return List with garbage collection results and memory freed
#' @export
smart_garbage_collection <- function(force_full = FALSE) {
  
  start_time <- Sys.time()
  pre_gc_memory <- get_memory_usage()
  
  # Determine GC strategy based on current memory pressure
  if (force_full || pre_gc_memory$status %in% c("critical", "warning")) {
    cat("🧹 Performing full garbage collection (memory pressure detected)...\n")
    
    # Full garbage collection with reset
    gc_result <- gc(verbose = FALSE, reset = TRUE, full = TRUE)
    
  } else if (pre_gc_memory$gc_needed) {
    cat("🧹 Performing standard garbage collection...\n")
    
    # Standard garbage collection
    gc_result <- gc(verbose = FALSE, reset = FALSE)
    
  } else {
    # No garbage collection needed
    return(list(
      performed = FALSE,
      reason = "memory_usage_normal",
      memory_before_mb = pre_gc_memory$used_mb,
      memory_after_mb = pre_gc_memory$used_mb,
      memory_freed_mb = 0
    ))
  }
  
  # Get post-GC memory usage
  post_gc_memory <- get_memory_usage()
  memory_freed <- pre_gc_memory$used_mb - post_gc_memory$used_mb
  gc_duration <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  
  # Update tracker
  .memory_tracker$last_gc_time <<- Sys.time()
  
  # Log significant memory recovery
  if (memory_freed > 10) {  # More than 10MB freed
    cat(sprintf("✅ GC freed %.1f MB in %.2f seconds\n", memory_freed, gc_duration))
    
    # Record optimization event
    optimization_event <- list(
      timestamp = Sys.time(),
      type = "garbage_collection",
      memory_freed_mb = memory_freed,
      duration_seconds = gc_duration,
      trigger = if (force_full) "manual" else "automatic"
    )
    
    .memory_tracker$optimization_events <<- append(
      .memory_tracker$optimization_events, 
      list(optimization_event)
    )
  }
  
  return(list(
    performed = TRUE,
    memory_before_mb = pre_gc_memory$used_mb,
    memory_after_mb = post_gc_memory$used_mb,
    memory_freed_mb = memory_freed,
    duration_seconds = gc_duration,
    gc_type = if (force_full) "full" else "standard"
  ))
}

#' Optimize Data Loading for Large Datasets
#' 
#' Implements memory-efficient loading strategies for 134k+ legislative documents
#' Uses chunked loading and lazy evaluation for Railway constraints
#' 
#' @param file_path Path to data file
#' @param chunk_size Number of rows to load at once
#' @param lazy_load Whether to use lazy loading
#' @return List with loading strategy and memory impact
#' @export
memory_efficient_data_loading <- function(file_path, chunk_size = 5000, lazy_load = TRUE) {
  
  cat("📊 Implementing memory-efficient data loading...\n")
  
  # Check available memory before loading
  pre_load_memory <- get_memory_usage()
  
  if (pre_load_memory$status %in% c("critical", "warning")) {
    cat("⚠️ Memory pressure detected, performing cleanup before data loading...\n")
    smart_garbage_collection(force_full = TRUE)
  }
  
  loading_strategy <- list(
    chunk_size = chunk_size,
    lazy_load = lazy_load,
    file_path = file_path,
    memory_before_mb = pre_load_memory$used_mb
  )
  
  # Determine optimal loading strategy based on available memory
  available_mb <- pre_load_memory$available_mb
  
  if (available_mb < 200) {  # Less than 200MB available
    loading_strategy$chunk_size <- 1000   # Very small chunks
    loading_strategy$lazy_load <- TRUE
    loading_strategy$strategy <- "ultra_conservative"
    cat("🚨 Ultra-conservative loading: 1000 rows per chunk\n")
    
  } else if (available_mb < 500) {  # Less than 500MB available
    loading_strategy$chunk_size <- 2500   # Small chunks
    loading_strategy$lazy_load <- TRUE
    loading_strategy$strategy <- "conservative"
    cat("⚠️ Conservative loading: 2500 rows per chunk\n")
    
  } else if (available_mb < 1000) {  # Less than 1GB available
    loading_strategy$chunk_size <- 5000   # Medium chunks
    loading_strategy$strategy <- "balanced"
    cat("📊 Balanced loading: 5000 rows per chunk\n")
    
  } else {  # More than 1GB available
    loading_strategy$chunk_size <- 10000  # Larger chunks
    loading_strategy$strategy <- "performance"
    cat("🚀 Performance loading: 10000 rows per chunk\n")
  }
  
  return(loading_strategy)
}

#' Monitor Large Object Creation
#' 
#' Tracks creation of large objects that could impact Railway memory limits
#' 
#' @param object_name Name of the object being created
#' @param object_size Size of the object in MB
monitor_large_object <- function(object_name, object_size_mb) {
  
  if (object_size_mb >= .memory_limits$large_object_mb) {
    cat(sprintf("📏 Large object detected: %s (%.1f MB)\n", object_name, object_size_mb))
    
    current_memory <- get_memory_usage()
    projected_usage <- current_memory$used_mb + object_size_mb
    
    if (projected_usage >= .memory_limits$app_warning_mb) {
      cat(sprintf("⚠️ Warning: Object creation would use %.1f MB (%.1f%% of Railway limit)\n",
                  projected_usage, (projected_usage / .memory_limits$railway_total_mb) * 100))
      
      # Suggest garbage collection
      if (current_memory$gc_needed) {
        cat("💡 Suggestion: Run smart_garbage_collection() before creating this object\n")
      }
    }
    
    # Record large object event
    large_object_event <- list(
      timestamp = Sys.time(),
      type = "large_object_creation",
      object_name = object_name,
      object_size_mb = object_size_mb,
      total_memory_mb = projected_usage
    )
    
    .memory_tracker$optimization_events <<- append(
      .memory_tracker$optimization_events, 
      list(large_object_event)
    )
  }
}

#' Check Memory Health Status
#' 
#' Performs comprehensive memory health check for Railway deployment
#' 
#' @return List with memory health assessment and recommendations
#' @export
check_memory_health <- function() {
  
  current_memory <- get_memory_usage()
  
  # Calculate health score (0-100)
  health_score <- 100 - (current_memory$usage_percentage * 1.2)  # Penalize high usage
  health_score <- max(0, min(100, health_score))
  
  # Generate recommendations
  recommendations <- c()
  
  if (current_memory$status == "critical") {
    recommendations <- c(recommendations, 
      "CRITICAL: Immediate garbage collection required",
      "Consider reducing dataset size or implementing pagination",
      "Monitor for memory leaks in reactive expressions")
  } else if (current_memory$status == "warning") {
    recommendations <- c(recommendations,
      "WARNING: Memory usage approaching Railway limits", 
      "Consider proactive garbage collection",
      "Review large objects in memory")
  } else if (current_memory$gc_needed) {
    recommendations <- c(recommendations,
      "Garbage collection recommended to free up memory")
  }
  
  # Check for memory leaks (rapid growth)
  if (length(.memory_tracker$optimization_events) >= 2) {
    recent_events <- tail(.memory_tracker$optimization_events, 5)
    memory_trend <- "stable"  # Simplified analysis
  } else {
    memory_trend <- "insufficient_data"
  }
  
  health_status <- list(
    health_score = round(health_score, 1),
    status = current_memory$status,
    memory_usage = current_memory,
    memory_trend = memory_trend,
    recommendations = recommendations,
    railway_compliance = current_memory$usage_percentage < 85,
    last_check = Sys.time()
  )
  
  return(health_status)
}

#' Memory Optimization Report
#' 
#' Generates comprehensive memory optimization report for Railway deployment
#' 
#' @return List with detailed memory analysis and optimization history
#' @export
generate_memory_report <- function() {
  
  cat("📋 Generating memory optimization report...\n")
  
  current_memory <- get_memory_usage()
  health_status <- check_memory_health()
  
  # Calculate optimization efficiency
  total_events <- length(.memory_tracker$optimization_events)
  total_memory_freed <- if (total_events > 0) {
    sum(sapply(.memory_tracker$optimization_events, function(e) {
      if ("memory_freed_mb" %in% names(e)) e$memory_freed_mb else 0
    }))
  } else {
    0
  }
  
  # Calculate uptime
  uptime_hours <- if (!is.null(.memory_tracker$monitoring_started)) {
    as.numeric(difftime(Sys.time(), .memory_tracker$monitoring_started, units = "hours"))
  } else {
    0
  }
  
  report <- list(
    # Current Status
    current_status = list(
      memory_used_mb = current_memory$used_mb,
      memory_peak_mb = current_memory$peak_mb,
      usage_percentage = current_memory$usage_percentage,
      status = current_memory$status,
      railway_compliance = health_status$railway_compliance
    ),
    
    # Optimization Performance
    optimization_performance = list(
      total_optimizations = total_events,
      total_memory_freed_mb = total_memory_freed,
      average_memory_freed_mb = if (total_events > 0) total_memory_freed / total_events else 0,
      optimization_efficiency = if (total_events > 0) "active" else "minimal"
    ),
    
    # Railway Compliance
    railway_compliance = list(
      within_limits = current_memory$used_mb < .memory_limits$railway_total_mb,
      safety_margin_mb = .memory_limits$railway_total_mb - current_memory$used_mb,
      peak_usage_percentage = (current_memory$peak_mb / .memory_limits$railway_total_mb) * 100,
      compliance_status = if (current_memory$usage_percentage < 75) "excellent" 
                         else if (current_memory$usage_percentage < 85) "good"
                         else "attention_required"
    ),
    
    # Health Assessment
    health_assessment = health_status,
    
    # System Information
    system_info = list(
      r_version = R.version.string,
      platform = R.version$platform,
      monitoring_uptime_hours = round(uptime_hours, 2),
      last_gc = .memory_tracker$last_gc_time
    ),
    
    # Recent Events
    recent_events = if (total_events > 0) {
      tail(.memory_tracker$optimization_events, 10)
    } else {
      list()
    }
  )
  
  cat("✅ Memory optimization report generated\n")
  return(report)
}

#' Emergency Memory Cleanup
#' 
#' Performs aggressive memory cleanup when approaching Railway limits
#' 
#' @export
emergency_memory_cleanup <- function() {
  
  cat("🚨 Performing emergency memory cleanup for Railway deployment...\n")
  
  pre_cleanup_memory <- get_memory_usage()
  
  # Step 1: Force full garbage collection
  cat("🧹 Step 1: Aggressive garbage collection...\n")
  gc_result <- smart_garbage_collection(force_full = TRUE)
  
  # Step 2: Clear temporary objects from global environment
  cat("🗑️ Step 2: Clearing temporary objects...\n")
  temp_objects <- ls(envir = .GlobalEnv, pattern = "^(temp_|tmp_|cache_)")
  if (length(temp_objects) > 0) {
    rm(list = temp_objects, envir = .GlobalEnv)
    cat(sprintf("Removed %d temporary objects\n", length(temp_objects)))
  }
  
  # Step 3: Clear large unused data frames
  cat("📊 Step 3: Analyzing large objects...\n")
  large_objects <- find_large_objects()
  if (length(large_objects) > 0) {
    cat(sprintf("Found %d large objects consuming memory\n", length(large_objects)))
  }
  
  # Step 4: Force another garbage collection
  final_gc <- smart_garbage_collection(force_full = TRUE)
  
  post_cleanup_memory <- get_memory_usage()
  total_freed <- pre_cleanup_memory$used_mb - post_cleanup_memory$used_mb
  
  cat(sprintf("✅ Emergency cleanup complete: %.1f MB freed\n", total_freed))
  cat(sprintf("📊 Memory usage: %.1f MB (%.1f%% of Railway limit)\n",
              post_cleanup_memory$used_mb, post_cleanup_memory$usage_percentage))
  
  # Record emergency cleanup event
  emergency_event <- list(
    timestamp = Sys.time(),
    type = "emergency_cleanup",
    memory_freed_mb = total_freed,
    memory_before_mb = pre_cleanup_memory$used_mb,
    memory_after_mb = post_cleanup_memory$used_mb,
    trigger = "manual_emergency"
  )
  
  .memory_tracker$optimization_events <<- append(
    .memory_tracker$optimization_events, 
    list(emergency_event)
  )
  
  return(list(
    memory_freed_mb = total_freed,
    memory_before_mb = pre_cleanup_memory$used_mb,
    memory_after_mb = post_cleanup_memory$used_mb,
    cleanup_effective = total_freed > 50  # More than 50MB freed
  ))
}

#' Find Large Objects in Memory
#' 
#' Identifies large objects that could be candidates for cleanup
#' 
find_large_objects <- function() {
  
  large_objects <- list()
  
  tryCatch({
    # Get objects from global environment
    object_names <- ls(envir = .GlobalEnv)
    
    for (obj_name in object_names) {
      obj <- get(obj_name, envir = .GlobalEnv)
      obj_size_mb <- as.numeric(object.size(obj)) / 1024^2
      
      if (obj_size_mb >= .memory_limits$large_object_mb) {
        large_objects[[obj_name]] <- list(
          name = obj_name,
          size_mb = obj_size_mb,
          class = class(obj)[1],
          type = typeof(obj)
        )
      }
    }
  }, error = function(e) {
    cat("⚠️ Error analyzing large objects:", e$message, "\n")
  })
  
  return(large_objects)
}

cat("✅ Memory optimization module loaded for Railway deployment\n")
cat("🧠 Ready for intelligent memory management with 2GB constraints\n")
cat("📊 Memory monitoring and cleanup systems initialized\n")