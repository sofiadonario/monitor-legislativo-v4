# Test Environment Setup Guide

This guide documents the required environment configuration for running the Monitor Legislativo v4 test suites.

## Overview

The test suites have been designed with **graceful degradation** - they will skip automatically if required dependencies or configuration are missing, rather than failing with errors.

## Test Suites

### 1. Scalar Safety Tests (Simple Integration Test)

**Location**: `tests/testthat/test-scalar-safety.R`

**Runner**: `tests/run-scalar-tests.R`

**Requirements**:
- ✅ No external dependencies
- ✅ No environment configuration needed
- ✅ Runs in any environment

**Run Command**:
```bash
Rscript tests/run-scalar-tests.R
```

---

### 2. Security Validation Tests

**Location**: `tests/security/comprehensive_security_validation.R`

**Requirements**:
- **Environment Variables**:
  - `RAILWAY_ENVIRONMENT` - Railway environment name (e.g., "production")
  - `DATABASE_URL` - PostgreSQL connection string
  - `LGPD_COMPLIANCE_ENABLED` (optional) - LGPD compliance flag

- **R Packages**:
  - `httr` - HTTP client
  - `jsonlite` - JSON processing
  - `digest` - Hashing functions

**Setup Example**:
```bash
export RAILWAY_ENVIRONMENT=production
export DATABASE_URL=postgresql://user:password@host:port/database
export LGPD_COMPLIANCE_ENABLED=true
```

**Run Command**:
```bash
Rscript tests/security/comprehensive_security_validation.R
```

**Skip Behavior**: If environment variables are missing, the test suite will skip with message:
```
⏭️  SKIPPING SECURITY TESTS: Production environment not configured
   Required: RAILWAY_ENVIRONMENT, DATABASE_URL
```

---

### 3. Production Test Suite

**Location**: `tests/production/comprehensive_production_test_suite.R`

**Requirements**:
- **Environment Variables**:
  - `RAILWAY_ENVIRONMENT` - Railway environment name
  - `DATABASE_URL` - PostgreSQL connection string
  - `USE_RAILWAY_DB` (optional) - Flag to use Railway database

- **R Packages**:
  - `dplyr` - Data manipulation
  - `DBI` - Database interface
  - `RPostgres` - PostgreSQL driver

**Setup Example**:
```bash
export RAILWAY_ENVIRONMENT=production
export DATABASE_URL=postgresql://user:password@host:port/database
export USE_RAILWAY_DB=true
```

**Run Command**:
```bash
Rscript tests/production/comprehensive_production_test_suite.R
```

**Skip Behavior**: If environment not configured:
```
⏭️  SKIPPING PRODUCTION TESTS: Production environment not configured
   Required: RAILWAY_ENVIRONMENT or DATABASE_URL
```

---

### 4. Performance/Load Tests

**Location**: `tests/performance/railway_load_testing.R`

**Requirements**:
- **Environment Variables**:
  - `RAILWAY_STATIC_URL` - Railway application URL (e.g., `https://your-app.railway.app`)
  - OR have app running on `http://localhost:3838`

- **R Packages**:
  - `httr` - HTTP client
  - `dplyr` - Data manipulation
  - `jsonlite` - JSON processing

**Setup Example**:
```bash
export RAILWAY_STATIC_URL=https://monitor-legislativo.railway.app
```

**Run Command**:
```bash
Rscript tests/performance/railway_load_testing.R
```

**Skip Behavior**: If no target URL detected:
```
⏭️  SKIPPING PERFORMANCE TESTS: No target URL detected
   Set RAILWAY_STATIC_URL or run app on localhost:3838
```

---

## Common Issues & Solutions

### Issue: "Database pool creation failed"

**Cause**: Missing PostgreSQL credentials or DATABASE_URL

**Solution**:
```bash
# Set DATABASE_URL with all connection parameters
export DATABASE_URL="postgresql://username:password@hostname:5432/database_name"

# OR set individual parameters
export PGHOST=hostname
export PGPORT=5432
export PGDATABASE=database_name
export PGUSER=username
export PGPASSWORD=password
```

### Issue: "Package 'shinyjs' not available"

**Cause**: Optional package not installed

**Solution**: The application now handles this gracefully - shinyjs features will be disabled but app will run. To enable:
```r
install.packages("shinyjs")
```

### Issue: "no loop for break/next, jumping to top level"

**Cause**: Fixed in railway_load_testing.R:95

**Status**: ✅ Resolved - error handler now uses `NULL` instead of `next`

### Issue: "object of type 'difftime' cannot be coerced to type 'character'"

**Cause**: difftime objects passed to JSON serialization

**Status**: ✅ Resolved - converted to numeric with `as.numeric(difftime(...))`

---

## Running All Tests

To run all available tests that can execute in your environment:

```bash
Rscript tests/run_available_tests.R
```

This script will:
1. Check environment configuration
2. Run tests that have their dependencies met
3. Skip tests that are missing requirements
4. Report results for all attempted tests

---

## Development Testing

For local development without full production setup:

```bash
# 1. Run scalar safety tests (always works)
Rscript tests/run-scalar-tests.R

# 2. Start app locally for integration testing
R -e "shiny::runApp()"

# 3. In another terminal, run performance tests
export RAILWAY_STATIC_URL=http://localhost:3838
Rscript tests/performance/railway_load_testing.R
```

---

## CI/CD Testing

For automated testing in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  env:
    RAILWAY_ENVIRONMENT: production
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
  run: |
    Rscript tests/run_available_tests.R
```

---

## Test Environment Checklist

Use this checklist to verify your test environment:

- [ ] R 4.3.3+ installed
- [ ] Core packages installed: `dplyr`, `DBI`, `RPostgres`, `httr`, `jsonlite`
- [ ] `DATABASE_URL` environment variable set (for DB tests)
- [ ] `RAILWAY_ENVIRONMENT` set to "production" (for full tests)
- [ ] Application accessible at URL or localhost:3838 (for performance tests)
- [ ] Optional: `shinyjs` installed for enhanced UI features
- [ ] Optional: `LGPD_COMPLIANCE_ENABLED` set for compliance tests

---

## Getting Help

If you encounter issues:

1. Check that test requirements are met for the specific suite
2. Review test output for skip messages
3. Verify environment variables are set correctly
4. Ensure required R packages are installed
5. Check application logs for detailed error information

For more information, see:
- [README.md](../README.md) - Main project documentation
- [TESTING.md](TESTING.md) - Detailed testing documentation
