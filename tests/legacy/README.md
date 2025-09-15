# Legacy Tests

This directory contains older test files that are no longer part of the main test suite.

## Moved Files
- `simple_geographic_test.R` - Basic geographic functionality tests
- `test_geographic_enhancements.R` - Geographic system enhancement tests  
- `test_geographic_system.R` - Geographic system integration tests
- `test_advanced_search.R` - Advanced search functionality tests

These tests were moved here during the test cleanup on 2025-09-15 to focus on the main testthat-based test suite in `tests/testthat/`.

## Current Test Structure
The main tests are now organized under:
- `tests/testthat/` - Main test suite using testthat framework
- `tests/test_runner_sprint8a.R` - Comprehensive test runner
- `tests/security/` - Security-focused tests

These legacy tests may contain useful test cases that could be integrated into the main test suite in the future.