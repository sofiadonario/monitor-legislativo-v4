#!/usr/bin/env python3
"""
Automated CSV Integrity Testing Suite

This script provides automated testing capabilities for CSV file integrity,
ensuring that cleaned files maintain data quality and can be reliably processed.

Author: Data Quality Assessment System
Date: 2025-07-26
"""

import pandas as pd
import numpy as np
import os
import json
import glob
import unittest
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import logging
from pathlib import Path
import chardet
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CSVIntegrityTestSuite(unittest.TestCase):
    """
    Automated test suite for CSV file integrity and data quality.
    """
    
    @classmethod
    def setUpClass(cls):
        """Set up test class with file paths and expected schema."""
        cls.data_directory = Path(os.getcwd())
        cls.cleaned_files = list(cls.data_directory.glob("*_cleaned.csv"))
        cls.test_results = {}
        
        # Expected schema
        cls.expected_columns = [
            "titulo", "tipo", "data", "urn", "autor", "assuntos", "classificacao", 
            "jurisdicao", "autoridade", "ementa", "url", "localidade", "numero", 
            "ano", "termo_busca", "data_coleta", "origem", "categoria", "modal", 
            "pais", "estado", "municipio", "fontes_localizacao"
        ]
        
        # Required columns (cannot be all empty)
        cls.required_columns = ["titulo", "categoria", "modal", "termo_busca", "data_coleta", "origem"]
        
        # Categorical constraints
        cls.categorical_constraints = {
            "categoria": ["Doutrina", "Legislação", "Jurisprudência", "Proposições", "Outros", ""],
            "modal": ["geral", "rodoviário", "marítimo", "aéreo", ""],
            "origem": ["extração_principal", ""],
            "pais": ["Brasil", ""]
        }
        
        logger.info(f"Test suite initialized for {len(cls.cleaned_files)} files")
    
    def detect_encoding(self, file_path: Path) -> str:
        """Detect file encoding."""
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read(10000)
                result = chardet.detect(raw_data)
                return result['encoding'] or 'utf-8'
        except:
            return 'utf-8'
    
    def test_file_accessibility(self):
        """Test that all cleaned files can be accessed and read."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                # Check file exists
                self.assertTrue(file_path.exists(), f"File {file_path.name} does not exist")
                
                # Check file is not empty
                self.assertGreater(file_path.stat().st_size, 0, f"File {file_path.name} is empty")
                
                # Check file can be read
                try:
                    encoding = self.detect_encoding(file_path)
                    with open(file_path, 'r', encoding=encoding) as f:
                        first_line = f.readline()
                        self.assertGreater(len(first_line), 0, f"Cannot read first line of {file_path.name}")
                except Exception as e:
                    self.fail(f"Cannot read file {file_path.name}: {str(e)}")
    
    def test_csv_parsing(self):
        """Test that all CSV files can be parsed without errors."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    
                    # Basic parsing checks
                    self.assertIsInstance(df, pd.DataFrame, f"Failed to create DataFrame from {file_path.name}")
                    self.assertGreater(len(df.columns), 0, f"No columns found in {file_path.name}")
                    
                except Exception as e:
                    self.fail(f"Failed to parse CSV file {file_path.name}: {str(e)}")
    
    def test_schema_consistency(self):
        """Test that all files have consistent schema."""
        schemas = []
        
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    df = pd.read_csv(file_path, encoding=encoding, nrows=1)
                    columns = list(df.columns)
                    schemas.append(columns)
                    
                    # Check expected columns are present
                    self.assertEqual(
                        columns, self.expected_columns,
                        f"Schema mismatch in {file_path.name}. Expected: {self.expected_columns}, Got: {columns}"
                    )
                    
                except Exception as e:
                    self.fail(f"Failed to check schema for {file_path.name}: {str(e)}")
        
        # Check all schemas are identical
        if schemas:
            first_schema = schemas[0]
            for i, schema in enumerate(schemas[1:], 1):
                self.assertEqual(
                    schema, first_schema,
                    f"Schema inconsistency between files. File {i+1} has different schema."
                )
    
    def test_required_columns_not_empty(self):
        """Test that required columns are not completely empty."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    
                    for column in self.required_columns:
                        if column in df.columns:
                            non_null_count = df[column].notna().sum()
                            self.assertGreater(
                                non_null_count, 0,
                                f"Required column '{column}' is completely empty in {file_path.name}"
                            )
                    
                except Exception as e:
                    self.fail(f"Failed to check required columns for {file_path.name}: {str(e)}")
    
    def test_categorical_value_constraints(self):
        """Test that categorical columns contain only expected values."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    
                    for column, expected_values in self.categorical_constraints.items():
                        if column in df.columns:
                            actual_values = set(df[column].dropna().astype(str))
                            expected_set = set(expected_values)
                            
                            unexpected_values = actual_values - expected_set
                            self.assertEqual(
                                len(unexpected_values), 0,
                                f"Unexpected values in column '{column}' in {file_path.name}: {list(unexpected_values)}"
                            )
                    
                except Exception as e:
                    self.fail(f"Failed to check categorical constraints for {file_path.name}: {str(e)}")
    
    def test_date_format_consistency(self):
        """Test that date columns have consistent formats."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    
                    # Test data column
                    if 'data' in df.columns:
                        non_null_dates = df['data'].dropna()
                        if len(non_null_dates) > 0:
                            # Try to parse dates
                            parsed_dates = pd.to_datetime(non_null_dates, errors='coerce')
                            invalid_count = parsed_dates.isna().sum()
                            
                            # Allow some invalid dates but not too many
                            invalid_ratio = invalid_count / len(non_null_dates)
                            self.assertLess(
                                invalid_ratio, 0.1,
                                f"Too many invalid dates in {file_path.name}: {invalid_count}/{len(non_null_dates)} ({invalid_ratio:.1%})"
                            )
                    
                    # Test data_coleta column (datetime)
                    if 'data_coleta' in df.columns:
                        non_null_datetimes = df['data_coleta'].dropna()
                        if len(non_null_datetimes) > 0:
                            parsed_datetimes = pd.to_datetime(non_null_datetimes, errors='coerce')
                            invalid_count = parsed_datetimes.isna().sum()
                            
                            # Should have no invalid datetimes as this is system-generated
                            self.assertEqual(
                                invalid_count, 0,
                                f"Invalid datetimes found in data_coleta column in {file_path.name}: {invalid_count}"
                            )
                    
                except Exception as e:
                    self.fail(f"Failed to check date formats for {file_path.name}: {str(e)}")
    
    def test_year_column_validity(self):
        """Test that year column contains valid year values."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    
                    if 'ano' in df.columns:
                        non_null_years = df['ano'].dropna()
                        if len(non_null_years) > 0:
                            # Convert to numeric
                            numeric_years = pd.to_numeric(non_null_years, errors='coerce')
                            valid_years = numeric_years.dropna()
                            
                            if len(valid_years) > 0:
                                min_year = valid_years.min()
                                max_year = valid_years.max()
                                current_year = datetime.now().year
                                
                                # Check reasonable year range
                                self.assertGreaterEqual(
                                    min_year, 1800,
                                    f"Year values too old in {file_path.name}: minimum year {min_year}"
                                )
                                self.assertLessEqual(
                                    max_year, current_year + 1,
                                    f"Year values in future in {file_path.name}: maximum year {max_year}"
                                )
                    
                except Exception as e:
                    self.fail(f"Failed to check year column for {file_path.name}: {str(e)}")
    
    def test_data_integrity_preservation(self):
        """Test that data integrity has been preserved during cleaning."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    
                    # Check for completely empty rows
                    empty_rows = df.isnull().all(axis=1).sum()
                    total_rows = len(df)
                    
                    if total_rows > 0:
                        empty_ratio = empty_rows / total_rows
                        self.assertLess(
                            empty_ratio, 0.5,
                            f"Too many empty rows in {file_path.name}: {empty_rows}/{total_rows} ({empty_ratio:.1%})"
                        )
                    
                    # Check for duplicate rows (should be minimal)
                    duplicate_count = df.duplicated().sum()
                    if total_rows > 0:
                        duplicate_ratio = duplicate_count / total_rows
                        self.assertLess(
                            duplicate_ratio, 0.1,
                            f"Too many duplicate rows in {file_path.name}: {duplicate_count}/{total_rows} ({duplicate_ratio:.1%})"
                        )
                    
                except Exception as e:
                    self.fail(f"Failed to check data integrity for {file_path.name}: {str(e)}")
    
    def test_encoding_consistency(self):
        """Test that all files use consistent encoding."""
        encodings = []
        
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                encoding = self.detect_encoding(file_path)
                encodings.append(encoding)
                
                # Check that encoding is UTF-8 or compatible
                self.assertIn(
                    encoding.lower().replace('-', ''),
                    ['utf8', 'utf8sig', 'ascii'],
                    f"File {file_path.name} uses unexpected encoding: {encoding}"
                )
        
        # Check encoding consistency across files
        if encodings:
            most_common_encoding = max(set(encodings), key=encodings.count)
            inconsistent_files = [
                self.cleaned_files[i].name for i, enc in enumerate(encodings) 
                if enc != most_common_encoding
            ]
            
            if inconsistent_files:
                logger.warning(f"Encoding inconsistency detected in files: {inconsistent_files}")
    
    def test_file_size_reasonableness(self):
        """Test that file sizes are reasonable (not too small or too large)."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                file_size_mb = file_path.stat().st_size / (1024 * 1024)
                
                # Check minimum size (at least header should be present)
                self.assertGreater(
                    file_size_mb, 0.001,  # 1KB minimum
                    f"File {file_path.name} is too small: {file_size_mb:.3f} MB"
                )
                
                # Check maximum size (reasonable upper bound)
                self.assertLess(
                    file_size_mb, 1000,  # 1GB maximum
                    f"File {file_path.name} is too large: {file_size_mb:.1f} MB"
                )
    
    def test_no_malformed_csv_structure(self):
        """Test that CSV structure is not malformed."""
        for file_path in self.cleaned_files:
            with self.subTest(file=file_path.name):
                try:
                    encoding = self.detect_encoding(file_path)
                    
                    # Read file line by line to check structure
                    with open(file_path, 'r', encoding=encoding) as f:
                        header_line = f.readline().strip()
                        
                        # Count expected columns in header
                        header_columns = len(header_line.split(','))
                        self.assertEqual(
                            header_columns, len(self.expected_columns),
                            f"Header column count mismatch in {file_path.name}: expected {len(self.expected_columns)}, got {header_columns}"
                        )
                        
                        # Check a few data lines for consistent column count
                        line_num = 2
                        for _ in range(min(10, sum(1 for _ in f))):  # Check up to 10 lines
                            line = f.readline().strip()
                            if line:  # Skip empty lines
                                # Simple column count check (not perfect due to quoted commas, but catches major issues)
                                if line.count('"') % 2 == 0:  # Even number of quotes (properly closed)
                                    # Remove quoted sections for column counting
                                    simplified_line = re.sub(r'"[^"]*"', 'X', line)
                                    column_count = len(simplified_line.split(','))
                                    
                                    self.assertEqual(
                                        column_count, len(self.expected_columns),
                                        f"Column count mismatch in {file_path.name} line {line_num}: expected {len(self.expected_columns)}, got {column_count}"
                                    )
                            line_num += 1
                    
                except Exception as e:
                    self.fail(f"Failed to check CSV structure for {file_path.name}: {str(e)}")

class CSVIntegrityTestRunner:
    """
    Test runner for CSV integrity tests with comprehensive reporting.
    """
    
    def __init__(self, data_directory: str):
        """Initialize test runner."""
        self.data_directory = Path(data_directory)
        self.test_results = {}
        self.timestamp = datetime.now()
    
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all integrity tests and generate comprehensive report.
        
        Returns:
            Dictionary containing test results and summary
        """
        logger.info("Starting CSV integrity test suite...")
        
        # Create test suite
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(CSVIntegrityTestSuite)
        
        # Run tests with custom result collector
        result_collector = CSVTestResultCollector()
        runner = unittest.TextTestRunner(stream=result_collector, verbosity=2)
        test_result = runner.run(suite)
        
        # Compile results
        results_summary = {
            "test_timestamp": self.timestamp.isoformat(),
            "total_tests": test_result.testsRun,
            "passed_tests": test_result.testsRun - len(test_result.failures) - len(test_result.errors),
            "failed_tests": len(test_result.failures),
            "error_tests": len(test_result.errors),
            "success_rate": round(((test_result.testsRun - len(test_result.failures) - len(test_result.errors)) / test_result.testsRun * 100), 2) if test_result.testsRun > 0 else 0,
            "test_details": {
                "failures": [{"test": str(test), "error": str(error)} for test, error in test_result.failures],
                "errors": [{"test": str(test), "error": str(error)} for test, error in test_result.errors]
            },
            "overall_status": "PASS" if test_result.wasSuccessful() else "FAIL",
            "cleaned_files_tested": len(CSVIntegrityTestSuite.cleaned_files),
            "recommendations": self._generate_test_recommendations(test_result)
        }
        
        logger.info(f"Test suite completed. Success rate: {results_summary['success_rate']:.1f}%")
        
        return results_summary
    
    def _generate_test_recommendations(self, test_result) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        if test_result.wasSuccessful():
            recommendations.append("All integrity tests passed! Data files are in excellent condition.")
        else:
            if test_result.failures:
                recommendations.append(f"{len(test_result.failures)} test failures detected. Review failed tests and address data quality issues.")
            
            if test_result.errors:
                recommendations.append(f"{len(test_result.errors)} test errors occurred. Check for structural or access issues with data files.")
            
            # Analyze specific failure patterns
            failure_messages = [str(error) for _, error in test_result.failures]
            error_messages = [str(error) for _, error in test_result.errors]
            all_messages = failure_messages + error_messages
            
            if any("schema" in msg.lower() for msg in all_messages):
                recommendations.append("Schema-related issues detected. Ensure all files have consistent column structure.")
            
            if any("encoding" in msg.lower() for msg in all_messages):
                recommendations.append("Encoding issues detected. Consider standardizing file encoding to UTF-8.")
            
            if any("categorical" in msg.lower() for msg in all_messages):
                recommendations.append("Categorical value issues detected. Review and standardize categorical data values.")
            
            if any("date" in msg.lower() for msg in all_messages):
                recommendations.append("Date format issues detected. Standardize date formats across all files.")
        
        return recommendations
    
    def save_test_report(self, test_results: Dict[str, Any], output_file: str = None) -> str:
        """Save test results to JSON file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.data_directory / f"csv_integrity_test_report_{timestamp}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(test_results, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Test report saved to {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to save test report: {e}")
            return ""

class CSVTestResultCollector:
    """Custom stream for collecting test output."""
    
    def __init__(self):
        self.output = []
    
    def write(self, text):
        self.output.append(text)
    
    def flush(self):
        pass

def main():
    """Main execution function."""
    import re  # Import here to avoid issues with test class
    
    # Get current directory
    current_dir = os.getcwd()
    
    # Run integrity tests
    test_runner = CSVIntegrityTestRunner(current_dir)
    test_results = test_runner.run_all_tests()
    
    # Save test report
    report_file = test_runner.save_test_report(test_results)
    
    # Print summary
    print("\n" + "="*80)
    print("CSV INTEGRITY TEST SUMMARY")
    print("="*80)
    print(f"Total tests: {test_results['total_tests']}")
    print(f"Passed: {test_results['passed_tests']}")
    print(f"Failed: {test_results['failed_tests']}")
    print(f"Errors: {test_results['error_tests']}")
    print(f"Success rate: {test_results['success_rate']:.1f}%")
    print(f"Overall status: {test_results['overall_status']}")
    print(f"Files tested: {test_results['cleaned_files_tested']}")
    print(f"Report saved to: {report_file}")
    print("\nRecommendations:")
    for i, rec in enumerate(test_results['recommendations'], 1):
        print(f"{i}. {rec}")
    print("="*80)

if __name__ == "__main__":
    main()