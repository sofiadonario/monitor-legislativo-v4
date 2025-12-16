# ============================================================================
# Monitor Legislativo API - Complete R Examples
# Sprint 7A (API-005) Implementation
# ============================================================================

# Install and load required packages
if (!require(httr)) install.packages("httr")
if (!require(jsonlite)) install.packages("jsonlite")
if (!require(dplyr)) install.packages("dplyr")
if (!require(ggplot2)) install.packages("ggplot2")
if (!require(leaflet)) install.packages("leaflet")

library(httr)
library(jsonlite)
library(dplyr)
library(ggplot2)
library(leaflet)

# API Configuration
API_BASE <- "https://mackmonitor-667999538255.southamerica-east1.run.app/api/v1"
API_KEY <- Sys.getenv("MONITOR_LEGISLATIVO_API_KEY", "demo_key_12345")

# Helper function for API requests
api_request <- function(endpoint, method = "GET", data = NULL) {
  url <- paste0(API_BASE, endpoint)
  headers <- add_headers(`X-API-Key` = API_KEY, `Content-Type` = "application/json")
  
  if (method == "GET") {
    response <- GET(url, headers)
  } else if (method == "POST") {
    response <- POST(url, headers, body = toJSON(data, auto_unbox = TRUE))
  }
  
  if (status_code(response) == 200) {
    return(fromJSON(content(response, "text")))
  } else {
    stop(paste("API Error:", status_code(response), content(response, "text")))
  }
}

# ============================================================================
# EXAMPLE 1: Basic Document Search
# ============================================================================

cat("📚 Example 1: Basic Document Search\n")
cat("=====================================\n")

# Simple text search
search_results <- api_request("/search/advanced", "POST", list(
  query = "direito constitucional",
  limit = 10,
  sort_by = "relevance"
))

cat("Found", length(search_results$data), "documents\n")
if (length(search_results$data) > 0) {
  cat("First result:", search_results$data[[1]]$title, "\n")
}

# ============================================================================
# EXAMPLE 2: Advanced Search with Filters
# ============================================================================

cat("\n🔍 Example 2: Advanced Search with Filters\n")
cat("==========================================\n")

advanced_search <- api_request("/legislation/advanced", "POST", list(
  query = "transporte público",
  states = c("SP", "RJ", "DF"),
  date_start = "2020-01-01",
  date_end = "2023-12-31",
  categories = c("municipal", "estadual"),
  limit = 50
))

cat("Advanced search found", length(advanced_search$results), "documents\n")

# Analyze results by state
if (length(advanced_search$results) > 0) {
  state_counts <- table(sapply(advanced_search$results, function(x) x$state))
  cat("Results by state:\n")
  print(state_counts)
}

# ============================================================================
# EXAMPLE 3: Geographic Analysis
# ============================================================================

cat("\n🗺️ Example 3: Geographic Analysis\n")
cat("=================================\n")

# Get comprehensive geographic analysis
geo_analysis <- api_request("/geographic/ibge-integration?analysis_type=comprehensive")

cat("Geographic analysis completed\n")
cat("States covered:", length(geo_analysis$states_data), "\n")

# Create a simple visualization of legislative activity by state
if (length(geo_analysis$states_data) > 0) {
  states_df <- do.call(rbind, lapply(names(geo_analysis$states_data), function(state) {
    data.frame(
      state = state,
      document_count = geo_analysis$states_data[[state]]$total_documents,
      stringsAsFactors = FALSE
    )
  }))
  
  # Simple bar plot
  p1 <- ggplot(states_df, aes(x = reorder(state, document_count), y = document_count)) +
    geom_bar(stat = "identity", fill = "steelblue") +
    coord_flip() +
    labs(title = "Legislative Documents by State",
         x = "State", y = "Number of Documents") +
    theme_minimal()
  
  print(p1)
}

# ============================================================================
# EXAMPLE 4: Academic Citations
# ============================================================================

cat("\n📖 Example 4: Academic Citations\n")
cat("================================\n")

# Generate citations for documents
if (length(search_results$data) > 0) {
  # Get first document ID
  doc_id <- search_results$data[[1]]$id
  
  # Generate ABNT citation
  citation_abnt <- api_request(paste0("/citations/generate?document_id=", doc_id, "&format=abnt"))
  
  cat("ABNT Citation:\n")
  cat(citation_abnt$citation, "\n\n")
  
  # Generate APA citation
  citation_apa <- api_request(paste0("/citations/generate?document_id=", doc_id, "&format=apa"))
  
  cat("APA Citation:\n")
  cat(citation_apa$citation, "\n\n")
}

# Bulk citation generation
if (length(search_results$data) >= 3) {
  doc_ids <- sapply(search_results$data[1:3], function(x) x$id)
  
  bulk_citations <- api_request("/citations/bulk-generate", "POST", list(
    document_ids = doc_ids,
    format = "abnt",
    include_metadata = TRUE
  ))
  
  cat("Generated", length(bulk_citations$citations), "bulk citations\n")
}

# ============================================================================
# EXAMPLE 5: Trend Analysis
# ============================================================================

cat("\n📈 Example 5: Trend Analysis\n")
cat("============================\n")

# Analyze trends for education legislation
education_trends <- api_request("/legislation/trends", "POST", list(
  query = "educação",
  time_period = "5years",
  group_by = "year",
  states = c("SP", "RJ", "MG")
))

cat("Education legislation trends analysis completed\n")

if (length(education_trends$trends) > 0) {
  # Create trends visualization
  trends_df <- do.call(rbind, lapply(names(education_trends$trends), function(year) {
    data.frame(
      year = as.numeric(year),
      count = education_trends$trends[[year]],
      stringsAsFactors = FALSE
    )
  }))
  
  p2 <- ggplot(trends_df, aes(x = year, y = count)) +
    geom_line(color = "darkred", size = 1.2) +
    geom_point(color = "darkred", size = 2) +
    labs(title = "Education Legislation Trends (5 Years)",
         x = "Year", y = "Number of Documents") +
    theme_minimal()
  
  print(p2)
}

# ============================================================================
# EXAMPLE 6: Export and Bulk Operations
# ============================================================================

cat("\n📦 Example 6: Export and Bulk Operations\n")
cat("========================================\n")

# Request research dataset export
export_request <- api_request("/export/research-dataset", "POST", list(
  query = "meio ambiente",
  format = "csv",
  fields = c("id", "title", "content", "state", "date", "category"),
  limit = 100,
  include_metadata = TRUE
))

cat("Export request submitted with ID:", export_request$export_id, "\n")

# Check export status (in real scenario, you'd poll this)
export_status <- api_request(paste0("/export/status?export_id=", export_request$export_id))
cat("Export status:", export_status$status, "\n")

# ============================================================================
# EXAMPLE 7: Real-time Monitoring
# ============================================================================

cat("\n⏰ Example 7: Real-time Monitoring\n")
cat("==================================\n")

# Get live activity feed
live_feed <- api_request("/monitoring/live-feed?limit=10")

cat("Latest", length(live_feed$activities), "activities:\n")
if (length(live_feed$activities) > 0) {
  for (i in 1:min(3, length(live_feed$activities))) {
    activity <- live_feed$activities[[i]]
    cat("-", activity$description, "(", activity$timestamp, ")\n")
  }
}

# Get activity summary
activity_summary <- api_request("/monitoring/activity-summary")
cat("\nActivity Summary:\n")
cat("- Today's documents:", activity_summary$today_documents, "\n")
cat("- This week:", activity_summary$week_documents, "\n")
cat("- Active states:", activity_summary$active_states, "\n")

# ============================================================================
# EXAMPLE 8: Spatial Analysis with Maps
# ============================================================================

cat("\n🗺️ Example 8: Interactive Maps\n")
cat("==============================\n")

# Get spatial clustering data
spatial_data <- api_request("/geographic/spatial-clustering", "POST", list(
  analysis_type = "state_level",
  include_correlations = TRUE,
  clustering_method = "hierarchical"
))

cat("Spatial clustering analysis completed\n")

# Create an interactive leaflet map (simplified version)
if (exists("spatial_data") && !is.null(spatial_data$clusters)) {
  # Sample Brazilian state coordinates (simplified)
  brazil_states <- data.frame(
    state = c("SP", "RJ", "MG", "DF", "RS", "PR"),
    lat = c(-23.5505, -22.9068, -19.9167, -15.7942, -30.0346, -25.2521),
    lng = c(-46.6333, -43.1729, -43.9345, -47.8822, -51.2177, -49.6760),
    stringsAsFactors = FALSE
  )
  
  # Create basic map
  map <- leaflet() %>%
    addTiles() %>%
    setView(lng = -47.8822, lat = -15.7942, zoom = 4)
  
  # Add markers for states with data
  for (i in 1:nrow(brazil_states)) {
    state <- brazil_states$state[i]
    if (state %in% names(geo_analysis$states_data)) {
      doc_count <- geo_analysis$states_data[[state]]$total_documents
      map <- map %>% addMarkers(
        lng = brazil_states$lng[i], 
        lat = brazil_states$lat[i],
        popup = paste(state, ":", doc_count, "documents")
      )
    }
  }
  
  cat("Interactive map created (view in RStudio Viewer or browser)\n")
  print(map)
}

# ============================================================================
# EXAMPLE 9: Content Analysis Pipeline
# ============================================================================

cat("\n📊 Example 9: Content Analysis Pipeline\n")
cat("=======================================\n")

# Advanced content analysis
content_analysis <- api_request("/analytics/content", "POST", list(
  query = "sustentabilidade",
  analysis_type = "comprehensive",
  include_keywords = TRUE,
  include_sentiment = TRUE,
  time_range = "2years"
))

cat("Content analysis completed\n")
if (!is.null(content_analysis$keywords)) {
  cat("Top keywords found:", length(content_analysis$keywords), "\n")
  if (length(content_analysis$keywords) > 0) {
    top_keywords <- head(content_analysis$keywords, 5)
    cat("- Top 5 keywords:", paste(names(top_keywords), collapse = ", "), "\n")
  }
}

# ============================================================================
# EXAMPLE 10: Academic Research Workflow
# ============================================================================

cat("\n🎓 Example 10: Complete Academic Workflow\n")
cat("=========================================\n")

# Step 1: Comprehensive search
research_query <- "política pública AND educação"
research_docs <- api_request("/legislation/advanced", "POST", list(
  query = research_query,
  states = c("SP", "RJ", "MG", "DF", "RS"),
  date_start = "2018-01-01",
  categories = c("federal", "estadual", "municipal"),
  limit = 200,
  sort_by = "relevance"
))

cat("Research corpus:", length(research_docs$results), "documents\n")

if (length(research_docs$results) > 0) {
  # Step 2: Generate comprehensive citations
  doc_ids <- sapply(research_docs$results[1:min(10, length(research_docs$results))], function(x) x$id)
  
  research_citations <- api_request("/citations/bulk-generate", "POST", list(
    document_ids = doc_ids,
    format = "abnt",
    include_metadata = TRUE,
    include_abstract = TRUE
  ))
  
  cat("Generated", length(research_citations$citations), "academic citations\n")
  
  # Step 3: Network analysis
  network_analysis <- api_request("/citations/network-analysis", "POST", list(
    document_ids = doc_ids,
    analysis_depth = "comprehensive",
    include_cross_references = TRUE
  ))
  
  if (!is.null(network_analysis$network_metrics)) {
    cat("Network analysis completed\n")
    cat("- Network density:", round(network_analysis$network_metrics$density, 3), "\n")
    cat("- Connected components:", network_analysis$network_metrics$components, "\n")
  }
  
  # Step 4: Export research package
  research_export <- api_request("/export/research-dataset", "POST", list(
    document_ids = doc_ids,
    format = "academic_bundle",
    include_citations = TRUE,
    include_analysis = TRUE,
    include_network_data = TRUE
  ))
  
  cat("Research package exported with ID:", research_export$export_id, "\n")
}

# ============================================================================
# EXAMPLE 11: Dashboard Analytics
# ============================================================================

cat("\n📊 Example 11: Dashboard Analytics\n")
cat("==================================\n")

# Get comprehensive dashboard metrics
dashboard_metrics <- api_request("/analytics/dashboard")

cat("Dashboard Analytics Summary:\n")
cat("- Total documents:", dashboard_metrics$total_documents, "\n")
cat("- States with documents:", dashboard_metrics$states_with_docs, "\n")
cat("- Municipalities with documents:", dashboard_metrics$municipalities_with_docs, "\n")
cat("- Date range:", dashboard_metrics$date_range_years, "years\n")
cat("- Last updated:", dashboard_metrics$last_updated, "\n")

# Get usage analytics
usage_analytics <- api_request("/analytics/usage")

if (!is.null(usage_analytics)) {
  cat("\nUsage Analytics:\n")
  cat("- API calls today:", usage_analytics$calls_today, "\n")
  cat("- Popular endpoints:", paste(usage_analytics$popular_endpoints[1:3], collapse = ", "), "\n")
}

# ============================================================================
# EXAMPLE 12: Performance Testing
# ============================================================================

cat("\n⚡ Example 12: Performance Testing\n")
cat("==================================\n")

# Test API response times
start_time <- Sys.time()
performance_test <- api_request("/search/advanced", "POST", list(
  query = "teste",
  limit = 1
))
end_time <- Sys.time()

response_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
cat("API response time:", round(response_time * 1000, 2), "ms\n")

# Get system health
health_check <- api_request("/monitoring/health")
cat("System status:", health_check$status, "\n")
cat("Database connection:", health_check$database, "\n")
cat("API version:", health_check$api_version, "\n")

# ============================================================================
# Summary
# ============================================================================

cat("\n", rep("=", 60), "\n")
cat("🎉 ALL EXAMPLES COMPLETED SUCCESSFULLY!\n")
cat(rep("=", 60), "\n")
cat("Sprint 7A API Examples demonstrate:\n")
cat("✅ Basic and advanced document search\n")
cat("✅ Geographic analysis with IBGE integration\n") 
cat("✅ Academic citation generation (ABNT/APA)\n")
cat("✅ Content analysis and trend identification\n")
cat("✅ Real-time monitoring and activity feeds\n")
cat("✅ Interactive mapping capabilities\n")
cat("✅ Export and bulk operations\n")
cat("✅ Complete academic research workflows\n")
cat("✅ Performance monitoring and analytics\n")
cat("✅ Brazilian legislative data compliance\n")
cat("\n📚 For more examples, see the API documentation at:\n")
cat("https://mackmonitor-667999538255.southamerica-east1.run.app/api/docs\n")
cat(rep("=", 60), "\n")