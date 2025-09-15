# Test Suite Organization

This directory contains the organized test suite for Monitor Legislativo v4.

## Directory Structure

```
tests/
├── README.md                    # This file
├── testthat.R                   # Main test configuration
├── unit/                        # Unit tests for individual components
│   ├── test_app_startup.R
│   └── test_data_loading.R
├── integration/                 # Integration and end-to-end tests
│   ├── test_e2e_user_journeys.R
│   ├── test_api_comprehensive.R
│   ├── simple_integration_test.R
│   └── basic_test_runner.R
├── performance/                 # Performance and load tests
│   └── test_performance_loads.R
├── security/                    # Security and compliance tests
│   ├── test_security_lgpd.R
│   └── test_security_functions.R
├── comprehensive/               # Comprehensive test runners
│   └── test_runner_sprint8a.R
└── legacy/                      # Archived older tests
    ├── README.md
    ├── simple_geographic_test.R
    ├── test_geographic_enhancements.R
    ├── test_geographic_system.R
    └── test_advanced_search.R
```

## Running Tests

### Individual Test Categories

```r
# Unit tests
testthat::test_dir("tests/unit")

# Integration tests  
testthat::test_dir("tests/integration")

# Performance tests
testthat::test_dir("tests/performance")

# Security tests
testthat::test_dir("tests/security")
```

### Comprehensive Test Suite

```r
# Run Sprint 8A comprehensive testing
source("tests/comprehensive/test_runner_sprint8a.R")
result <- main_sprint8a_testing()
```

### All Tests

```r
# Run all organized tests
testthat::test_dir("tests/unit")
testthat::test_dir("tests/integration") 
testthat::test_dir("tests/performance")
testthat::test_dir("tests/security")
```

## Test Categories

### Unit Tests
- **test_app_startup.R**: Basic application startup validation
- **test_data_loading.R**: Data loading and structure validation

### Integration Tests
- **test_e2e_user_journeys.R**: End-to-end user workflow testing
- **test_api_comprehensive.R**: API endpoint validation (38+ endpoints)
- **simple_integration_test.R**: Basic integration validation
- **basic_test_runner.R**: Framework-independent test runner

### Performance Tests
- **test_performance_loads.R**: Load testing and response time validation

### Security Tests
- **test_security_lgpd.R**: LGPD compliance and security validation
- **test_security_functions.R**: Security function testing

### Comprehensive Testing
- **test_runner_sprint8a.R**: Production readiness assessment (529 lines)
  - Academic research workflow validation
  - Performance benchmarking
  - Security compliance verification
  - Production readiness certification

## Dependencies

- **testthat**: Main testing framework
- **shinytest2**: Shiny application testing
- **R6**: Object-oriented programming support

## Notes

- Tests are organized by purpose and scope
- Legacy tests preserved in `tests/legacy/`
- Data paths updated to use `data_current/` directory
- Comprehensive reporting available through Sprint 8A framework