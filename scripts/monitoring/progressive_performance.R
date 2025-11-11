
# PERFORMANCE MONITORING ENHANCEMENT FOR PROGRESSIVE LOADING
# =========================================================

#' Monitor progressive loading performance
monitor_progressive_performance <- function() {
  list(
    memory_used_mb = round(sum(gc()[,"(Mb)"]), 1),
    max_memory_mb = 1500,  # Railway limit
    timestamp = Sys.time(),
    performance_ok = sum(gc()[,"(Mb)"]) < 1200
  )
}

#' Create performance alert if needed
check_performance_alert <- function() {
  perf <- monitor_progressive_performance()
  if (!perf$performance_ok) {
    list(
      type = "warning",
      message = paste("High memory usage:", perf$memory_used_mb, "MB /", perf$max_memory_mb, "MB")
    )
  } else {
    NULL
  }
}

cat("✅ Progressive loading performance monitoring loaded\n")
