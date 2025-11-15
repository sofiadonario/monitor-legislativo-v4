# Monitor Legislativo v4 - Detailed Implementation Plan

**Plan Version:** 1.0
**Created:** November 15, 2025
**Duration:** 10 weeks
**Total Effort:** 560-760 hours
**Team Size:** 2-3 senior developers

---

## 📅 Implementation Timeline Overview

```
Week 1-2:  🚨 CRITICAL SECURITY  (5 critical fixes)
Week 3-4:  ⚡ PERFORMANCE         (6 major optimizations)
Week 5-6:  📋 LGPD COMPLIANCE     (7 compliance tasks)
Week 7-8:  ✨ OPTIMIZATION        (6 enhancements)
Week 9-10: 🧪 TESTING & MONITORING (5 infrastructure tasks)
```

---

## PHASE 1: CRITICAL SECURITY (Weeks 1-2)

**Goal:** Eliminate all critical and high-severity vulnerabilities
**Duration:** 80 hours (2 weeks, 2 developers)
**Success Criteria:** 0 critical vulnerabilities, security scan passing

### Task 1.1: Remove Hardcoded Credentials
**Priority:** CRITICAL | **Effort:** 4 hours | **Risk:** HIGH

#### Steps:
1. **Identify all hardcoded credentials** (1 hour)
   ```bash
   grep -r "password.*=.*['\"]" R/ modules/ app_phoenix.R
   ```
   - `R/database/connection.R:291` - "postgres"
   - `analysis/urn_parsing/urn_pattern_analysis.R` - "Sdonario1"

2. **Remove and replace with env vars** (2 hours)
   ```r
   # Before:
   password = "postgres"

   # After:
   password = Sys.getenv("PGPASSWORD", "")
   if (password == "") {
     stop("PGPASSWORD environment variable required. Set in .Renviron or system env.")
   }
   ```

3. **Update documentation** (0.5 hour)
   - Add to README.md: Required environment variables
   - Create `.env.template` with all required vars

4. **Verify and test** (0.5 hour)
   ```bash
   # Test without PGPASSWORD - should fail fast
   # Test with PGPASSWORD - should connect
   ```

**Files to Modify:**
- `R/database/connection.R`
- `analysis/urn_parsing/urn_pattern_analysis.R`
- `.env.template` (create)
- `README.md`

**Testing:**
- [ ] App fails with clear error when PGPASSWORD missing
- [ ] App connects successfully with PGPASSWORD set
- [ ] No passwords in `git grep password`

---

### Task 1.2: Implement Parameterized Queries
**Priority:** CRITICAL | **Effort:** 16 hours | **Risk:** HIGH

#### Steps:
1. **Create parameterized query wrapper** (3 hours)
   ```r
   # File: R/database/safe_queries.R
   execute_safe_query <- function(pool, query, params = list()) {
     # Validate params
     if (length(params) > 0 && !is.list(params)) {
       stop("params must be a list")
     }

     # Log query (sanitized)
     log_query(substr(query, 1, 100), length(params))

     # Execute with parameters
     conn <- pool::poolCheckout(pool)
     on.exit(pool::poolReturn(conn))

     tryCatch({
       DBI::dbGetQuery(conn, query, params = params)
     }, error = function(e) {
       log_error("Query failed", e$message)
       stop("Database query failed")
     })
   }
   ```

2. **Refactor app_phoenix.R queries** (8 hours)
   - Line 1163-1164: Search query
   - Line 1168-1169: Tipo filter
   - Line 1219-1223: Stats queries
   - Line 1997-2005: Analytics queries

   ```r
   # Before:
   search_term <- gsub("'", "''", current_search)
   conditions <- c(conditions, paste0("titulo ILIKE '%", search_term, "%'"))

   # After:
   query <- "SELECT * FROM documents WHERE titulo ILIKE $1 AND tipo = $2 LIMIT $3"
   params <- list(
     paste0("%", current_search, "%"),
     current_tipo,
     as.integer(current_mostrar)
   )
   result <- execute_safe_query(db_pool, query, params)
   ```

3. **Refactor R/database/queries.R** (3 hours)
   - Line 305: Dynamic column query
   - All filter queries

4. **Add validation tests** (2 hours)
   ```r
   # tests/testthat/test_parameterized_queries.R
   test_that("SQL injection attempts fail safely", {
     malicious_input <- "'; DROP TABLE documents; --"
     result <- execute_safe_query(pool,
       "SELECT * FROM documents WHERE titulo ILIKE $1",
       list(malicious_input))
     expect_equal(nrow(result), 0)  # No results, no SQL execution
   })
   ```

**Files to Modify:**
- `R/database/safe_queries.R` (create)
- `app_phoenix.R` (multiple locations)
- `R/database/queries.R`
- `modules/data_service.R`
- `tests/testthat/test_parameterized_queries.R` (create)

**Testing:**
- [ ] All queries use parameterization
- [ ] SQL injection tests pass
- [ ] Performance not degraded
- [ ] Error handling works correctly

---

### Task 1.3: Add CSRF Protection
**Priority:** CRITICAL | **Effort:** 8 hours | **Risk:** HIGH

#### Steps:
1. **Integrate security hardening module** (2 hours)
   ```r
   # In app_phoenix.R, line 30:
   source("R/security/security_hardening.R")
   security <- init_security_hardening()
   ```

2. **Generate CSRF tokens** (2 hours)
   ```r
   # In server function:
   server <- function(input, output, session) {
     # Initialize security
     csrf_token <- security$generate_csrf_token(session)
     session$userData$csrf_token <- csrf_token

     # Add token to UI
     output$csrf_token_ui <- renderUI({
       tags$input(type = "hidden", id = "csrf_token", value = csrf_token)
     })
   }
   ```

3. **Validate on state-changing operations** (3 hours)
   ```r
   # Wrap all observeEvent with CSRF validation
   observeEvent(input$library_apply, {
     # Validate CSRF
     if (!security$validate_csrf_token(input$csrf_token, session)) {
       showNotification("Invalid security token. Please refresh the page.",
                       type = "error", duration = 10)
       return()
     }

     # Proceed with action
     filters$search <- input$library_search
     # ...
   })
   ```

4. **Add CSRF tests** (1 hour)
   ```r
   test_that("CSRF validation rejects invalid tokens", {
     session <- MockShinySession$new()
     result <- validate_csrf_token("invalid_token", session)
     expect_false(result$valid)
   })
   ```

**Files to Modify:**
- `app_phoenix.R` (server function, all observeEvent blocks)
- `R/security/security_hardening.R` (verify integration)
- `tests/security/test_csrf_protection.R` (create)

**Testing:**
- [ ] Valid tokens accepted
- [ ] Invalid tokens rejected
- [ ] Tokens expire after 60 minutes
- [ ] Security tests pass

---

### Task 1.4: Integrate Input Validation
**Priority:** HIGH | **Effort:** 16 hours | **Risk:** MEDIUM

#### Steps:
1. **Create validation service** (4 hours)
   ```r
   # R/security/input_validation.R
   validate_search_input <- function(input, max_length = 500) {
     # Check length
     if (nchar(input) > max_length) {
       return(list(valid = FALSE, error = "Input too long",
                  sanitized = substr(input, 1, max_length)))
     }

     # Check for SQL injection patterns
     sql_patterns <- c("DROP", "DELETE", "INSERT", "UPDATE", "EXEC")
     if (any(grepl(paste(sql_patterns, collapse = "|"), input, ignore.case = TRUE))) {
       return(list(valid = FALSE, error = "Invalid characters detected"))
     }

     # Check for XSS patterns
     xss_patterns <- c("<script", "javascript:", "onerror=", "onclick=")
     if (any(grepl(paste(xss_patterns, collapse = "|"), input, ignore.case = TRUE))) {
       return(list(valid = FALSE, error = "Invalid HTML detected"))
     }

     # Sanitize
     sanitized <- htmltools::htmlEscape(input)

     return(list(valid = TRUE, sanitized = sanitized, original = input))
   }
   ```

2. **Integrate into all inputs** (8 hours)
   ```r
   # In reactive expressions:
   library_data <- reactive({
     # Validate search term
     search_validation <- validate_search_input(input$library_search)
     if (!search_validation$valid) {
       showNotification(search_validation$error, type = "error")
       return(data.frame())
     }

     search_term <- search_validation$sanitized
     # ... use validated input
   })
   ```

3. **Add client-side validation** (2 hours)
   ```r
   # Add maxlength to all text inputs
   textInput("library_search", "Search:", maxlength = 500)

   # Add pattern validation
   textInput("year_input", "Year:", pattern = "[0-9]{4}")
   ```

4. **Create validation tests** (2 hours)

**Files to Modify:**
- `R/security/input_validation.R` (create)
- `app_phoenix.R` (all input handlers)
- `modules/*_server.R` (all modules with user input)
- `tests/security/test_input_validation.R` (create)

**Testing:**
- [ ] SQL injection attempts blocked
- [ ] XSS attempts blocked
- [ ] Length limits enforced
- [ ] Valid inputs accepted

---

### Task 1.5: Add Security Headers
**Priority:** HIGH | **Effort:** 4 hours | **Risk:** LOW

#### Steps:
1. **Add headers to Shiny app** (2 hours)
   ```r
   # In app_phoenix.R startup:
   options(shiny.http.response.filter = function(request, response) {
     # Security headers
     response$headers[["X-Frame-Options"]] <- "DENY"
     response$headers[["X-Content-Type-Options"]] <- "nosniff"
     response$headers[["X-XSS-Protection"]] <- "1; mode=block"
     response$headers[["Strict-Transport-Security"]] <-
       "max-age=31536000; includeSubDomains"
     response$headers[["Content-Security-Policy"]] <-
       "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline';"
     response$headers[["Referrer-Policy"]] <- "strict-origin-when-cross-origin"

     response
   })
   ```

2. **Verify headers in production** (1 hour)
   ```bash
   curl -I https://mackmonitor-app.com | grep -E "X-Frame|Content-Security"
   ```

3. **Add header tests** (1 hour)

**Files to Modify:**
- `app_phoenix.R`
- `tests/security/test_security_headers.R` (create)

---

### Task 1.6: Security Audit & Documentation
**Priority:** HIGH | **Effort:** 16 hours | **Risk:** LOW

#### Steps:
1. **Run automated security scan** (2 hours)
   - OWASP ZAP scan
   - Bandit (Python code)
   - Brakeman equivalent for R

2. **Manual code review** (6 hours)
   - Review all database queries
   - Review all user input handling
   - Review session management

3. **Document security measures** (4 hours)
   - Create SECURITY.md
   - Document threat model
   - Document mitigation strategies

4. **Create security checklist** (2 hours)

5. **Train team on secure coding** (2 hours)

**Deliverables:**
- Security audit report
- SECURITY.md
- Security checklist
- Team training materials

---

## PHASE 2: PERFORMANCE OPTIMIZATION (Weeks 3-4)

**Goal:** 80% performance improvement, 50+ concurrent users
**Duration:** 96 hours (2 weeks, 2 developers)
**Success Criteria:** <5s cold start, <1s queries, 50+ user load test passing

### Task 2.1: Implement Connection Pooling
**Priority:** CRITICAL | **Effort:** 16 hours | **Risk:** MEDIUM

#### Steps:
1. **Create connection pool manager** (4 hours)
   ```r
   # R/database/pool_manager.R
   library(pool)

   .db_pool <- NULL

   init_db_pool <- function() {
     if (!is.null(.db_pool)) {
       # Test existing pool
       tryCatch({
         pool::dbGetQuery(.db_pool, "SELECT 1")
         return(.db_pool)
       }, error = function(e) {
         pool::poolClose(.db_pool)
         .db_pool <<- NULL
       })
     }

     config <- get_database_config()

     .db_pool <<- pool::dbPool(
       drv = RPostgres::Postgres(),
       host = config$host,
       port = config$port,
       dbname = config$dbname,
       user = config$user,
       password = config$password,
       minSize = 5,
       maxSize = 20,
       idleTimeout = 600000,  # 10 minutes
       validationInterval = 60000  # 1 minute
     )

     # Register cleanup
     reg.finalizer(.GlobalEnv, function(e) {
       if (!is.null(.db_pool)) {
         pool::poolClose(.db_pool)
       }
     }, onexit = TRUE)

     .db_pool
   }

   get_db_pool <- function() {
     if (is.null(.db_pool)) {
       init_db_pool()
     }
     .db_pool
   }
   ```

2. **Replace global connection** (6 hours)
   ```r
   # In app_phoenix.R:
   # Replace line 321:
   # secure_db_connection <- init_secure_database()

   # With:
   source("R/database/pool_manager.R")
   db_pool <- init_db_pool()
   DB_AVAILABLE <- !is.null(db_pool)
   ```

3. **Update all query calls** (4 hours)
   ```r
   # Replace:
   dbGetQuery(secure_db_connection, query)

   # With:
   pool::dbGetQuery(db_pool, query, params = params)

   # Or use wrapper:
   execute_safe_query(db_pool, query, params)
   ```

4. **Add pool monitoring** (2 hours)
   ```r
   monitor_pool <- function() {
     stats <- pool::dbGetInfo(db_pool)
     cat("Pool stats:",
         "Free:", stats$free,
         "Taken:", stats$taken,
         "Total:", stats$total, "\n")
   }
   ```

**Files to Modify:**
- `R/database/pool_manager.R` (create)
- `app_phoenix.R`
- All files with `dbGetQuery` calls (~50 files)

**Testing:**
- [ ] Pool initializes successfully
- [ ] Queries execute correctly
- [ ] Concurrent requests handled (load test: 50 users)
- [ ] Pool cleanup on app shutdown

---

### Task 2.2: Implement Caching System
**Priority:** CRITICAL | **Effort:** 24 hours | **Risk:** MEDIUM

#### Steps:
1. **Initialize cache system** (4 hours)
   ```r
   # In app_phoenix.R, line 30:
   source("R/utils/cache_utils.R")
   cache_system <- init_cache_system(
     backend = "memory",  # or "redis" for production
     max_size_mb = 500,
     default_ttl = 3600  # 1 hour
   )
   ```

2. **Create cache wrapper** (4 hours)
   ```r
   # R/database/cached_queries.R
   cached_query <- function(pool, query, params = list(), ttl = 3600) {
     # Generate cache key
     key <- generate_cache_key(query, params)

     # Check cache
     cached <- cache_get(key)
     if (!is.null(cached)) {
       log_cache_hit(key)
       return(cached)
     }

     # Execute query
     result <- execute_safe_query(pool, query, params)

     # Store in cache
     cache_set(key, result, ttl = ttl)
     log_cache_miss(key)

     result
   }
   ```

3. **Implement cache for static data** (8 hours)
   ```r
   # Home statistics (lines 1219-1223)
   home_stats <- reactive({
     cached_query(
       db_pool,
       "SELECT
          COUNT(*) as total,
          COUNT(DISTINCT tipo) as types,
          MAX(data) as latest,
          MIN(data) as oldest
        FROM documents",
       params = list(),
       ttl = 3600  # 1 hour TTL
     )
   })
   ```

4. **Implement cache for search results** (6 hours)
   ```r
   search_results <- reactive({
     # Include filters in cache key
     cached_query(
       db_pool,
       "SELECT * FROM documents WHERE titulo ILIKE $1 AND tipo = $2 LIMIT $3",
       params = list(input$search, input$tipo, input$limit),
       ttl = 900  # 15 minutes
     )
   })
   ```

5. **Add cache monitoring** (2 hours)
   ```r
   observe({
     invalidateLater(60000)  # Every minute
     stats <- get_cache_stats()
     cat("Cache hit rate:", stats$hit_rate, "%\n")
   })
   ```

**Cache Strategy:**
| Data Type | TTL | Invalidation |
|-----------|-----|--------------|
| Static stats | 1 hour | Manual on data update |
| Search results | 15 min | Auto-expire |
| Geographic data | 30 min | Auto-expire |
| Document types | 1 hour | Manual on data update |
| User preferences | Session | On logout |

**Files to Modify:**
- `R/database/cached_queries.R` (create)
- `app_phoenix.R` (all reactive queries)
- `modules/data_service.R`

**Testing:**
- [ ] Cache hit rate >70% after warmup
- [ ] Stale data invalidated correctly
- [ ] Memory usage within limits
- [ ] Cache cleared on app restart

---

### Task 2.3: Add Server-Side Pagination
**Priority:** CRITICAL | **Effort:** 16 hours | **Risk:** LOW

#### Steps:
1. **Create pagination helper** (4 hours)
   ```r
   # R/utils/pagination.R
   paginate_query <- function(base_query, page = 1, page_size = 50) {
     offset <- (page - 1) * page_size

     # Add COUNT(*) OVER() for total
     query_with_count <- gsub(
       "SELECT",
       "SELECT COUNT(*) OVER() as total_rows,",
       base_query,
       fixed = TRUE
     )

     # Add LIMIT and OFFSET
     paginated_query <- paste(
       query_with_count,
       "LIMIT", page_size,
       "OFFSET", offset
     )

     paginated_query
   }
   ```

2. **Add pagination controls to UI** (4 hours)
   ```r
   # In library UI:
   fluidRow(
     column(6,
       numericInput("page_size", "Rows per page:", value = 50,
                   min = 10, max = 500, step = 10)
     ),
     column(6,
       div(style = "margin-top: 25px;",
         actionButton("prev_page", "Previous"),
         textOutput("page_info", inline = TRUE),
         actionButton("next_page", "Next")
       )
     )
   )
   ```

3. **Implement pagination logic** (6 hours)
   ```r
   # Server logic:
   page <- reactiveVal(1)

   observeEvent(input$next_page, {
     page(page() + 1)
   })

   observeEvent(input$prev_page, {
     if (page() > 1) page(page() - 1)
   })

   library_data <- reactive({
     base_query <- "SELECT * FROM documents WHERE ..."
     query <- paginate_query(base_query, page(), input$page_size)
     result <- cached_query(db_pool, query)

     # Extract total from first row
     if (nrow(result) > 0) {
       total_rows <- result$total_rows[1]
       result$total_rows <- NULL
       attr(result, "total") <- total_rows
     }

     result
   })

   output$page_info <- renderText({
     total <- attr(library_data(), "total") %||% 0
     paste("Page", page(), "of", ceiling(total / input$page_size))
   })
   ```

4. **Add pagination tests** (2 hours)

**Files to Modify:**
- `R/utils/pagination.R` (create)
- `app_phoenix.R` (library module)
- `modules/library_enhanced_module.R`
- `tests/unit/test_pagination.R` (create)

**Testing:**
- [ ] First page loads correctly
- [ ] Next/Previous navigation works
- [ ] Page counts accurate
- [ ] Large datasets paginate correctly

---

### Task 2.4: Optimize Database Queries
**Priority:** HIGH | **Effort:** 24 hours | **Risk:** MEDIUM

#### Steps:
1. **Integrate query optimizer** (6 hours)
   ```r
   # In app_phoenix.R:
   source("R/database/query_optimizer.R")
   optimizer <- init_database_query_optimizer(
     db_connection = db_pool,
     create_indexes = TRUE,
     enable_monitoring = TRUE
   )
   ```

2. **Replace dbGetQuery with optimized version** (10 hours)
   ```r
   # Replace:
   result <- dbGetQuery(pool, query)

   # With:
   result <- execute_optimized_query(
     query = query,
     params = params,
     cache_results = TRUE,
     explain = FALSE  # Set TRUE to see query plans
   )
   ```

3. **Analyze slow queries** (4 hours)
   ```r
   # Enable query logging
   enable_query_logging(threshold_ms = 1000)

   # Review slow queries
   slow_queries <- get_slow_queries()
   ```

4. **Create missing indexes** (4 hours)
   ```sql
   -- Based on query analysis
   CREATE INDEX idx_documents_titulo_gin
     ON documents USING gin(to_tsvector('portuguese', titulo));

   CREATE INDEX idx_documents_search_composite
     ON documents (estado, tipo, data DESC)
     WHERE titulo IS NOT NULL;
   ```

**Files to Modify:**
- `app_phoenix.R`
- All query execution points
- `database/migrations/004_optimization_indexes.sql` (create)

**Expected Improvements:**
- Document search: 3-8s → 0.5-1s (85% faster)
- Dashboard stats: 800ms → 100ms (87% faster)
- Geographic queries: 5-15s → 1-2s (85% faster)

---

### Task 2.5: Add Reactive Debouncing
**Priority:** HIGH | **Effort:** 8 hours | **Risk:** LOW

#### Steps:
1. **Install shinyWidgets** (0.5 hour)
   ```r
   install.packages("shinyWidgets")
   ```

2. **Add debouncing to search inputs** (4 hours)
   ```r
   # In server function:
   library(shinyWidgets)

   # Debounce search input (500ms delay)
   search_debounced <- debounce(reactive(input$library_search), 500)

   # Use debounced value in reactive
   library_data <- reactive({
     search_term <- search_debounced()  # Only triggers 500ms after last keystroke
     # ... query logic
   })
   ```

3. **Add throttling to filter changes** (2 hours)
   ```r
   # Throttle geographic filters (1 second max frequency)
   geo_filters_throttled <- throttle(reactive({
     list(
       tipo = input$geo_filter_tipo,
       date_start = input$geo_date_range[1],
       date_end = input$geo_date_range[2]
     )
   }), 1000)
   ```

4. **Add loading indicators** (1.5 hours)
   ```r
   output$search_loading <- renderUI({
     if (search_debounced() != input$library_search) {
       div(class = "loading-indicator", "Searching...")
     }
   })
   ```

**Files to Modify:**
- `app_phoenix.R` (all search inputs)
- `modules/*_server.R` (filter inputs)

**Expected Impact:**
- 90% reduction in queries while typing
- Better user experience
- Reduced server load

---

### Task 2.6: Cache Geographic Data
**Priority:** HIGH | **Effort:** 8 hours | **Risk:** LOW

#### Steps:
1. **Download and save GeoJSON locally** (2 hours)
   ```bash
   mkdir -p data/geo
   curl -o data/geo/brazil_states.geojson \
     https://raw.githubusercontent.com/codeforamerica/click_that_hood/master/public/data/brazil-states.geojson
   ```

2. **Load GeoJSON on startup** (2 hours)
   ```r
   # In global.R or app startup:
   brazil_shapefile <- reactiveVal(NULL)

   # Load once
   observe({
     if (is.null(brazil_shapefile())) {
       local_path <- "data/geo/brazil_states.geojson"

       if (file.exists(local_path)) {
         shp <- sf::st_read(local_path, quiet = TRUE)
       } else {
         # Fallback to download
         url <- "https://raw.githubusercontent.com/..."
         shp <- sf::st_read(url, quiet = TRUE)
         sf::st_write(shp, local_path)
       }

       # Simplify for performance
       shp <- sf::st_simplify(shp, preserveTopology = TRUE, dTolerance = 0.01)

       brazil_shapefile(shp)
       cat("✅ Geographic data loaded\n")
     }
   })
   ```

3. **Use cached shapefile** (3 hours)
   ```r
   # In geographic module:
   enhanced_geo_data <- reactive({
     shp <- brazil_shapefile()  # Use cached data

     # Merge with document data
     data %>%
       left_join(shp %>% select(sigla, geometry), by = c("estado" = "sigla"))
   })
   ```

4. **Add .gitignore entry** (0.5 hour)
   ```bash
   echo "data/geo/*.geojson" >> .gitignore
   ```

**Files to Modify:**
- `global.R` or `app_phoenix.R` startup
- `modules/geographic_enhanced.R`
- `.gitignore`
- `data/geo/` (create directory)

**Expected Impact:**
- 95% faster map loads (no external download)
- Eliminates external dependency
- 90% reduction in network traffic

---

## PHASE 3: LGPD COMPLIANCE (Weeks 5-6)

**Goal:** Full LGPD compliance, audit readiness
**Duration:** 96 hours
**Success Criteria:** ANPD checklist 100% compliant

### Task 3.1: Create Data Processing Register
**Priority:** HIGH | **Effort:** 16 hours | **Risk:** MEDIUM

#### Steps:
1. **Document all data processing activities** (6 hours)
   ```r
   # R/lgpd/processing_register.R
   create_processing_register <- function() {
     list(
       controller = list(
         name = "Universidade Presbiteriana Mackenzie",
         contact = "dpo@mackenzie.br",
         address = "Rua da Consolação, 930, São Paulo, SP"
       ),

       activities = list(
         legislative_search = list(
           id = "ACT-001",
           purpose = "Academic research on Brazilian legislative documents",
           legal_basis = "Art. 7º, IV - legitimate interest for academic research",
           data_categories = c(
             "Search queries",
             "User preferences",
             "Access logs",
             "Session data"
           ),
           data_subjects = c("Researchers", "Students", "Public users"),
           recipients = "None - data not shared with third parties",
           retention_period = "5 years (academic research standard)",
           cross_border_transfer = "None",
           security_measures = c(
             "Encryption in transit (TLS 1.3)",
             "Encryption at rest (AES-256)",
             "Access controls (RBAC)",
             "Audit logging",
             "Regular security audits"
           )
         ),

         user_authentication = list(
           id = "ACT-002",
           purpose = "User access control and session management",
           legal_basis = "Art. 7º, V - execution of contract",
           # ... similar structure
         )
       )
     )
   }
   ```

2. **Create register UI** (4 hours)
   - Admin-only access
   - Display all processing activities
   - Export to PDF

3. **Integrate with audit system** (4 hours)
   - Link to audit logs
   - Track changes to register
   - Version control

4. **Create documentation** (2 hours)
   - Processing register PDF
   - Submit to legal review

**Deliverable:** Comprehensive data processing register

---

### Task 3.2: Implement Cookie Consent
**Priority:** HIGH | **Effort:** 16 hours | **Risk:** LOW

#### Steps:
1. **Create consent banner UI** (6 hours)
   ```r
   # In UI:
   tags$div(
     id = "cookie-consent-banner",
     class = "cookie-consent",
     style = "position: fixed; bottom: 0; width: 100%; background: #333; color: white; padding: 20px; z-index: 9999;",
     p("Este site utiliza cookies para melhorar sua experiência e análise de uso."),
     tags$a(href = "/privacy-policy", "Política de Privacidade"),
     actionButton("accept_cookies", "Aceitar", class = "btn-success"),
     actionButton("reject_cookies", "Rejeitar", class = "btn-secondary")
   )
   ```

2. **Implement consent logic** (4 hours)
   ```r
   # Server:
   observeEvent(input$accept_cookies, {
     session$userData$cookies_accepted <- TRUE
     js$hideCookieBanner()
     log_user_consent("accepted", session$token)
   })

   observeEvent(input$reject_cookies, {
     session$userData$cookies_accepted <- FALSE
     js$hideCookieBanner()
     disable_analytics()
     log_user_consent("rejected", session$token)
   })
   ```

3. **Persist consent** (4 hours)
   ```r
   # Store in database
   store_user_consent <- function(user_id, consent_type, accepted) {
     dbExecute(pool,
       "INSERT INTO user_consents (user_id, consent_type, accepted, timestamp)
        VALUES ($1, $2, $3, NOW())",
       params = list(user_id, consent_type, accepted))
   }
   ```

4. **Add withdrawal mechanism** (2 hours)
   - User settings page
   - One-click withdrawal
   - Confirmation email

**Deliverable:** Cookie consent system

---

### Task 3.3: Build Data Subject Rights Portal
**Priority:** HIGH | **Effort:** 40 hours | **Risk:** MEDIUM

#### Steps:
1. **Design portal UI** (8 hours)
   - Request data access (Art. 18, I-II)
   - Request data correction (Art. 18, III)
   - Request data deletion (Art. 18, VI)
   - Request data portability (Art. 18, V)
   - Object to processing (Art. 18, §2)

2. **Implement data access** (8 hours)
   ```r
   # User requests all their data
   export_user_data <- function(user_id) {
     user_data <- list(
       profile = get_user_profile(user_id),
       searches = get_user_searches(user_id),
       preferences = get_user_preferences(user_id),
       audit_log = get_user_audit_log(user_id)
     )

     # Create JSON export
     json_data <- jsonlite::toJSON(user_data, pretty = TRUE)

     # Log access request
     log_data_access_request(user_id, "export")

     json_data
   }
   ```

3. **Implement data deletion** (8 hours)
   ```r
   # Right to be forgotten
   delete_user_data <- function(user_id, confirm = FALSE) {
     if (!confirm) {
       stop("Confirmation required")
     }

     # Anonymize or delete
     dbExecute(pool, "DELETE FROM user_searches WHERE user_id = $1", list(user_id))
     dbExecute(pool, "DELETE FROM user_preferences WHERE user_id = $1", list(user_id))
     dbExecute(pool, "UPDATE users SET deleted = TRUE WHERE id = $1", list(user_id))

     # Log deletion
     log_data_deletion(user_id)

     # Send confirmation email
     send_deletion_confirmation(user_id)
   }
   ```

4. **Implement data correction** (8 hours)
5. **Add request tracking** (4 hours)
6. **Create admin review workflow** (4 hours)

**Deliverable:** Self-service data rights portal

---

### Task 3.4: Add Audit Logging
**Priority:** HIGH | **Effort:** 24 hours | **Risk:** LOW

#### Steps:
1. **Create audit log schema** (4 hours)
   ```sql
   CREATE TABLE audit_log (
     id SERIAL PRIMARY KEY,
     timestamp TIMESTAMP DEFAULT NOW(),
     user_id INTEGER REFERENCES users(id),
     session_id VARCHAR(255),
     ip_address INET,
     action VARCHAR(100),
     resource_type VARCHAR(100),
     resource_id INTEGER,
     details JSONB,
     result VARCHAR(50)
   );

   CREATE INDEX idx_audit_log_user ON audit_log(user_id, timestamp DESC);
   CREATE INDEX idx_audit_log_action ON audit_log(action, timestamp DESC);
   ```

2. **Create logging functions** (8 hours)
   ```r
   # R/lgpd/audit_logging.R
   log_user_action <- function(
     action,
     resource_type = NULL,
     resource_id = NULL,
     details = list(),
     session = NULL
   ) {
     # Extract session info
     user_id <- session$userData$user_id %||% NULL
     session_id <- session$token %||% "unknown"
     ip_address <- session$clientData$url_hostname %||% "unknown"

     # Insert log
     dbExecute(pool,
       "INSERT INTO audit_log
        (user_id, session_id, ip_address, action, resource_type, resource_id, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7)",
       params = list(
         user_id, session_id, ip_address, action,
         resource_type, resource_id, jsonlite::toJSON(details)
       ))
   }
   ```

3. **Integrate into all actions** (10 hours)
   ```r
   # In all observeEvent blocks:
   observeEvent(input$library_apply, {
     log_user_action(
       action = "search_documents",
       details = list(
         search_term = input$library_search,
         tipo = input$library_tipo,
         limit = input$library_mostrar
       ),
       session = session
     )

     # Execute search...
   })
   ```

4. **Create audit log viewer** (2 hours)
   - Admin-only UI
   - Filter by user, action, date
   - Export to CSV

**Deliverable:** Comprehensive audit logging system

---

### Task 3.5: Create Privacy Policy
**Priority:** MEDIUM | **Effort:** 16 hours | **Risk:** LOW

#### Steps:
1. **Draft privacy policy** (8 hours)
   - Work with legal team
   - Include all LGPD requirements
   - Translate to Portuguese

2. **Create privacy policy page** (4 hours)
   ```r
   # In UI:
   tabPanel("Política de Privacidade",
     includeMarkdown("docs/privacy_policy_pt.md")
   )
   ```

3. **Link from all pages** (2 hours)
4. **Get legal approval** (2 hours)

**Deliverable:** Published privacy policy

---

### Task 3.6: Add DPO Information
**Priority:** MEDIUM | **Effort:** 4 hours | **Risk:** LOW

#### Steps:
1. **Add DPO contact to footer** (2 hours)
   ```r
   tags$footer(
     class = "app-footer",
     p("Data Protection Officer (DPO): dpo@mackenzie.br"),
     p("Para questões sobre privacidade, entre em contato com nosso DPO.")
   )
   ```

2. **Create DPO contact page** (2 hours)

**Deliverable:** DPO contact information displayed

---

### Task 3.7: Document Breach Notification Procedure
**Priority:** HIGH | **Effort:** 8 hours | **Risk:** LOW

#### Steps:
1. **Create breach response plan** (4 hours)
   - Incident detection
   - Assessment (severity, scope)
   - Containment
   - ANPD notification (72 hours)
   - User notification
   - Remediation

2. **Create notification templates** (2 hours)
3. **Train team on procedure** (2 hours)

**Deliverable:** Breach notification procedure document

---

## PHASE 4: OPTIMIZATION & POLISH (Weeks 7-8)

**Goal:** Production-grade reliability and UX
**Duration:** 96 hours

### Task 4.1: Implement Transaction Support
**Priority:** HIGH | **Effort:** 16 hours

#### Steps:
1. **Create transaction wrapper** (4 hours)
   ```r
   execute_in_transaction <- function(pool, operations) {
     conn <- pool::poolCheckout(pool)
     on.exit(pool::poolReturn(conn))

     tryCatch({
       DBI::dbBegin(conn)
       result <- operations(conn)
       DBI::dbCommit(conn)
       return(result)
     }, error = function(e) {
       DBI::dbRollback(conn)
       log_transaction_rollback(e$message)
       stop(e)
     })
   }
   ```

2. **Wrap multi-step operations** (8 hours)
3. **Add transaction tests** (4 hours)

---

### Task 4.2: Lazy Module Loading
**Priority:** HIGH | **Effort:** 16 hours

See implementation details in performance section.

---

### Task 4.3: Add leafletProxy Optimization
**Priority:** MEDIUM | **Effort:** 16 hours

See implementation details in performance section.

---

### Task 4.4: Standardize Error Handling
**Priority:** MEDIUM | **Effort:** 16 hours

#### Steps:
1. **Create error code system** (4 hours)
2. **Standardize error responses** (8 hours)
3. **Add user-friendly messages** (4 hours)

---

### Task 4.5: Add Loading Indicators
**Priority:** MEDIUM | **Effort:** 8 hours

#### Steps:
1. **Add spinners to all async operations** (4 hours)
   ```r
   shinycssloaders::withSpinner(
     leafletOutput("geo_map"),
     type = 6,
     color = "#3c8dbc"
   )
   ```

2. **Add progress bars for long tasks** (4 hours)

---

### Task 4.6: Accessibility Improvements
**Priority:** MEDIUM | **Effort:** 24 hours

#### Steps:
1. **Add ARIA labels** (8 hours)
2. **Test keyboard navigation** (8 hours)
3. **Verify color contrast** (4 hours)
4. **Screen reader testing** (4 hours)

---

## PHASE 5: TESTING & MONITORING (Weeks 9-10)

**Goal:** 80%+ test coverage, production monitoring
**Duration:** 96 hours

### Task 5.1: Security Test Suite
**Priority:** HIGH | **Effort:** 24 hours

#### Steps:
1. **SQL injection tests** (8 hours)
2. **XSS tests** (8 hours)
3. **CSRF tests** (4 hours)
4. **Authentication tests** (4 hours)

---

### Task 5.2: Integration Tests
**Priority:** HIGH | **Effort:** 32 hours

#### Steps:
1. **User journey tests** (16 hours)
2. **API integration tests** (8 hours)
3. **Database integration tests** (8 hours)

---

### Task 5.3: Performance Tests
**Priority:** HIGH | **Effort:** 16 hours

#### Steps:
1. **Load tests (50 concurrent users)** (8 hours)
2. **Stress tests** (4 hours)
3. **Memory leak tests** (4 hours)

---

### Task 5.4: Monitoring Dashboard
**Priority:** HIGH | **Effort:** 24 hours

#### Steps:
1. **Set up Prometheus/Grafana** (8 hours)
2. **Create dashboards** (8 hours)
3. **Configure alerts** (8 hours)

---

### Task 5.5: Documentation
**Priority:** MEDIUM | **Effort:** 16 hours

#### Steps:
1. **API documentation** (8 hours)
2. **Deployment guide** (4 hours)
3. **Troubleshooting guide** (4 hours)

---

## 📊 Resource Allocation

### Team Structure

**Recommended Team:**
- **Senior R Developer** (Lead): 40 hrs/week
- **Senior R Developer**: 40 hrs/week
- **Security Specialist** (Part-time): 10 hrs/week (Weeks 1-2, 5-6)
- **DevOps Engineer** (Part-time): 10 hrs/week (Weeks 9-10)
- **QA Engineer** (Part-time): 20 hrs/week (Weeks 9-10)

### Timeline with Milestones

```
Week 1:  Security fixes (Critical)
Week 2:  Security complete + testing
         ✓ MILESTONE: Zero critical vulnerabilities

Week 3:  Performance - Connection pool + caching
Week 4:  Performance - Pagination + optimization
         ✓ MILESTONE: <5s startup, 50+ concurrent users

Week 5:  LGPD - Data register + consent
Week 6:  LGPD - Rights portal + audit logging
         ✓ MILESTONE: LGPD compliance 100%

Week 7:  Optimization - Transactions + lazy loading
Week 8:  Optimization - UX improvements
         ✓ MILESTONE: Production-grade UX

Week 9:  Testing - Security + integration tests
Week 10: Testing - Performance tests + monitoring
         ✓ MILESTONE: 80%+ coverage, monitoring live

Week 11: Production deployment
Week 12: Monitoring + optimization
```

---

## 🎯 Success Criteria

### Phase 1: Security
- [ ] 0 critical vulnerabilities
- [ ] 0 high vulnerabilities
- [ ] Automated security tests passing
- [ ] Security audit approved

### Phase 2: Performance
- [ ] Cold startup <5 seconds
- [ ] Search queries <1 second
- [ ] Map rendering <2 seconds
- [ ] 50+ concurrent users supported
- [ ] 87% reduction in database queries

### Phase 3: LGPD
- [ ] Data processing register complete
- [ ] Cookie consent implemented
- [ ] Data rights portal functional
- [ ] Audit logging active
- [ ] Privacy policy published
- [ ] Legal review approved

### Phase 4: Optimization
- [ ] Transaction support implemented
- [ ] Lazy loading functional
- [ ] Error handling standardized
- [ ] Loading indicators added
- [ ] WCAG AA compliance verified

### Phase 5: Testing & Monitoring
- [ ] Test coverage >80%
- [ ] CI/CD pipeline functional
- [ ] Monitoring dashboard live
- [ ] Alerting configured
- [ ] Documentation complete

---

## 💵 Budget Breakdown

| Phase | Duration | Hours | Cost (R$ 400/hr) |
|-------|----------|-------|------------------|
| Phase 1: Security | 2 weeks | 100h | R$ 40,000 |
| Phase 2: Performance | 2 weeks | 120h | R$ 48,000 |
| Phase 3: LGPD | 2 weeks | 128h | R$ 51,200 |
| Phase 4: Optimization | 2 weeks | 96h | R$ 38,400 |
| Phase 5: Testing | 2 weeks | 120h | R$ 48,000 |
| **Total** | **10 weeks** | **564h** | **R$ 225,600** |

**Contingency (15%):** R$ 33,840
**Total with Contingency:** R$ 259,440

---

## 📝 Risk Management

### High Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Database migration issues | Medium | High | Extensive testing, rollback plan |
| Performance regression | Low | High | Continuous benchmarking |
| LGPD legal changes | Low | Medium | Legal review at each phase |
| Team availability | Medium | Medium | Cross-training, documentation |

### Medium Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Third-party API changes | Low | Medium | Local caching, fallbacks |
| Browser compatibility | Low | Low | Cross-browser testing |
| Load testing infrastructure | Medium | Low | Cloud-based load testing |

---

## 📞 Support & Escalation

### Issue Escalation Path

**Level 1:** Developer team (response: 2 hours)
**Level 2:** Tech lead (response: 4 hours)
**Level 3:** CTO/Architecture team (response: 8 hours)

### Critical Issue Response

**Security incident:** Immediate escalation to security team
**Production outage:** Immediate escalation to on-call engineer
**Data breach:** Immediate escalation to legal + LGPD team

---

## 🎓 Knowledge Transfer

### Documentation Deliverables

1. **Technical Architecture Document**
2. **API Documentation (Swagger)**
3. **Database Schema Documentation**
4. **Deployment Runbook**
5. **Troubleshooting Guide**
6. **Security Best Practices**
7. **LGPD Compliance Manual**

### Training Sessions

**Week 6:** LGPD compliance training (4 hours)
**Week 8:** Security best practices (4 hours)
**Week 10:** System architecture overview (8 hours)

---

## 🚀 Go-Live Checklist

### Pre-Production

- [ ] All critical fixes deployed
- [ ] Security scan clean
- [ ] Performance benchmarks met
- [ ] LGPD compliance verified
- [ ] Legal approval obtained
- [ ] Monitoring configured
- [ ] Alerts tested
- [ ] Backup strategy verified
- [ ] Rollback plan tested
- [ ] Documentation complete

### Production Deployment

- [ ] Database backup created
- [ ] Maintenance window scheduled
- [ ] Team on standby
- [ ] Monitoring active
- [ ] Rollback plan ready
- [ ] Communication sent to users

### Post-Deployment

- [ ] Smoke tests passed
- [ ] Performance metrics normal
- [ ] Error rates acceptable
- [ ] User feedback collected
- [ ] Incident response ready

---

**Plan Approved By:** _________________
**Date:** _________________
**Next Review:** End of Week 2 (Post-Security Phase)
