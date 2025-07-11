# Test script for cache implementation
source("R/cache_utils.R")

# Initialize cache
init_cache()

# Test cache functionality
test_data <- data.frame(
  id = 1:5,
  name = c("Test1", "Test2", "Test3", "Test4", "Test5"),
  value = c(10, 20, 30, 40, 50)
)

# Generate cache key
cache_key <- generate_cache_key("test_data", "sample")
print(paste("Cache key:", cache_key))

# Store data in cache
store_cached_result(cache_key, test_data, use_file_cache = TRUE)

# Retrieve data from cache
cached_data <- get_cached_result(cache_key, use_file_cache = TRUE)
print("Cached data retrieved:")
print(cached_data)

# Get cache statistics
stats <- get_cache_stats()
print("Cache statistics:")
print(stats)