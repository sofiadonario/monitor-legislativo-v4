#!/usr/bin/env python3
"""
Comprehensive Data Validation and Quality Assessment System for Cleaned CSV Files

This script performs extensive validation and quality checks on the cleaned LexML dataset files,
including schema consistency, data type validation, range checks, and data integrity verification.

Author: Data Quality Assessment System
Date: 2025-07-26
"""

import pandas as pd
import numpy as np
import os
import json
import glob
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import logging
from pathlib import Path
import chardet
import warnings

# Suppress pandas warnings for cleaner output
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_validation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ComprehensiveDataValidator:
    """
    Comprehensive data validation and quality assessment system for cleaned CSV files.
    """
    
    def __init__(self, data_directory: str):
        """
        Initialize the validator with the directory containing cleaned CSV files.
        
        Args:
            data_directory: Path to directory containing the cleaned CSV files
        """
        self.data_directory = Path(data_directory)
        self.cleaned_files = list(self.data_directory.glob("*_cleaned.csv"))
        self.validation_results = {}
        self.quality_metrics = {}
        self.schema_definition = {}
        self.validation_timestamp = datetime.now()
        
        # Expected schema based on the sample data
        self.expected_columns = [
            "titulo", "tipo", "data", "urn", "autor", "assuntos", "classificacao", 
            "jurisdicao", "autoridade", "ementa", "url", "localidade", "numero", 
            "ano", "termo_busca", "data_coleta", "origem", "categoria", "modal", 
            "pais", "estado", "municipio", "fontes_localizacao"
        ]
        
        # Data type expectations
        self.column_types = {
            "titulo": "string",
            "tipo": "string", 
            "data": "date",
            "urn": "string",
            "autor": "string",
            "assuntos": "text",
            "classificacao": "string",
            "jurisdicao": "categorical",
            "autoridade": "string",
            "ementa": "text",
            "url": "string",
            "localidade": "string",
            "numero": "string",
            "ano": "integer",
            "termo_busca": "string",
            "data_coleta": "datetime",
            "origem": "categorical",
            "categoria": "categorical",
            "modal": "categorical",
            "pais": "categorical",
            "estado": "categorical",
            "municipio": "string",
            "fontes_localizacao": "string"
        }
        
        # Expected categorical values
        self.categorical_values = {
            "jurisdicao": ["Federal", "Estadual", "Municipal", ""],
            "origem": ["extração_principal", ""],
            "categoria": ["Doutrina", "Legislação", "Jurisprudência", "Proposições", "Outros", ""],
            "modal": ["geral", "rodoviário", "marítimo", "aéreo", ""],
            "pais": ["Brasil", ""]
        }
        
        logger.info(f"Initialized validator for {len(self.cleaned_files)} cleaned CSV files")
    
    def detect_file_encoding(self, file_path: Path) -> str:
        """
        Detect the encoding of a CSV file.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Detected encoding
        """
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read(10000)  # Read first 10KB for detection
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                confidence = result['confidence']
                
                logger.info(f"Detected encoding for {file_path.name}: {encoding} (confidence: {confidence:.2f})")
                return encoding
        except Exception as e:
            logger.warning(f"Failed to detect encoding for {file_path}: {e}. Using utf-8.")
            return 'utf-8'
    
    def validate_csv_structure(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate the basic structure of a CSV file.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Dictionary containing structural validation results
        """
        result = {
            "file_name": file_path.name,
            "file_size_mb": file_path.stat().st_size / (1024 * 1024),
            "encoding": None,
            "can_read": False,
            "row_count": 0,
            "column_count": 0,
            "has_header": False,
            "delimiter": None,
            "structural_issues": []
        }
        
        try:
            # Detect encoding
            encoding = self.detect_file_encoding(file_path)
            result["encoding"] = encoding
            
            # Try to read the file
            df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
            result["can_read"] = True
            result["row_count"] = len(df)
            result["column_count"] = len(df.columns)
            result["has_header"] = True
            result["delimiter"] = ","  # CSV files use comma delimiter
            
            # Check for empty file
            if len(df) == 0:
                result["structural_issues"].append("File is empty")
            
            # Check for duplicate column names
            if len(df.columns) != len(set(df.columns)):
                result["structural_issues"].append("Duplicate column names detected")
            
            # Check for unnamed columns
            unnamed_cols = [col for col in df.columns if col.startswith('Unnamed:')]
            if unnamed_cols:
                result["structural_issues"].append(f"Unnamed columns found: {unnamed_cols}")
            
            logger.info(f"Successfully validated structure of {file_path.name}: {result['row_count']} rows, {result['column_count']} columns")
            
        except Exception as e:
            result["structural_issues"].append(f"Failed to read file: {str(e)}")
            logger.error(f"Failed to validate structure of {file_path}: {e}")
        
        return result
    
    def validate_schema_consistency(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate that the file schema matches the expected schema.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Dictionary containing schema validation results
        """
        result = {
            "file_name": file_path.name,
            "schema_valid": False,
            "missing_columns": [],
            "extra_columns": [],
            "column_order_correct": False,
            "schema_issues": []
        }
        
        try:
            df = pd.read_csv(file_path, encoding=self.detect_file_encoding(file_path), nrows=1)
            actual_columns = list(df.columns)
            
            # Check for missing columns
            missing = [col for col in self.expected_columns if col not in actual_columns]
            result["missing_columns"] = missing
            
            # Check for extra columns
            extra = [col for col in actual_columns if col not in self.expected_columns]
            result["extra_columns"] = extra
            
            # Check column order
            result["column_order_correct"] = actual_columns == self.expected_columns
            
            # Overall schema validity
            result["schema_valid"] = len(missing) == 0 and len(extra) == 0 and result["column_order_correct"]
            
            if missing:
                result["schema_issues"].append(f"Missing columns: {missing}")
            if extra:
                result["schema_issues"].append(f"Extra columns: {extra}")
            if not result["column_order_correct"]:
                result["schema_issues"].append("Column order does not match expected schema")
            
            logger.info(f"Schema validation for {file_path.name}: {'PASS' if result['schema_valid'] else 'FAIL'}")
            
        except Exception as e:
            result["schema_issues"].append(f"Failed to validate schema: {str(e)}")
            logger.error(f"Failed to validate schema for {file_path}: {e}")
        
        return result
    
    def validate_data_types(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate data types for each column.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Dictionary containing data type validation results
        """
        result = {
            "file_name": file_path.name,
            "type_validation_passed": True,
            "column_type_issues": {},
            "type_conversion_suggestions": {}
        }
        
        try:
            df = pd.read_csv(file_path, encoding=self.detect_file_encoding(file_path), low_memory=False)
            
            for column in df.columns:
                if column in self.column_types:
                    expected_type = self.column_types[column]
                    column_issues = []
                    
                    # Skip empty columns
                    if df[column].isna().all():
                        continue
                    
                    # Validate specific data types
                    if expected_type == "date":
                        # Check date format
                        date_issues = self._validate_date_column(df[column], column)
                        if date_issues:
                            column_issues.extend(date_issues)
                    
                    elif expected_type == "datetime":
                        # Check datetime format
                        datetime_issues = self._validate_datetime_column(df[column], column)
                        if datetime_issues:
                            column_issues.extend(datetime_issues)
                    
                    elif expected_type == "integer":
                        # Check integer values
                        integer_issues = self._validate_integer_column(df[column], column)
                        if integer_issues:
                            column_issues.extend(integer_issues)
                    
                    elif expected_type == "categorical":
                        # Check categorical values
                        if column in self.categorical_values:
                            categorical_issues = self._validate_categorical_column(df[column], column)
                            if categorical_issues:
                                column_issues.extend(categorical_issues)
                    
                    if column_issues:
                        result["column_type_issues"][column] = column_issues
                        result["type_validation_passed"] = False
            
            logger.info(f"Data type validation for {file_path.name}: {'PASS' if result['type_validation_passed'] else 'FAIL'}")
            
        except Exception as e:
            result["column_type_issues"]["general"] = [f"Failed to validate data types: {str(e)}"]
            result["type_validation_passed"] = False
            logger.error(f"Failed to validate data types for {file_path}: {e}")
        
        return result
    
    def _validate_date_column(self, series: pd.Series, column_name: str) -> List[str]:
        """Validate date column format."""
        issues = []
        non_null_values = series.dropna()
        
        if len(non_null_values) == 0:
            return issues
        
        # Try to parse dates
        try:
            parsed_dates = pd.to_datetime(non_null_values, errors='coerce')
            invalid_dates = parsed_dates.isna().sum()
            
            if invalid_dates > 0:
                issues.append(f"{invalid_dates} invalid date values found")
            
            # Check date ranges (reasonable years)
            valid_dates = parsed_dates.dropna()
            if len(valid_dates) > 0:
                min_year = valid_dates.dt.year.min()
                max_year = valid_dates.dt.year.max()
                current_year = datetime.now().year
                
                if min_year < 1800:
                    issues.append(f"Date values too old (minimum year: {min_year})")
                if max_year > current_year + 1:
                    issues.append(f"Date values in future (maximum year: {max_year})")
        
        except Exception as e:
            issues.append(f"Failed to parse dates: {str(e)}")
        
        return issues
    
    def _validate_datetime_column(self, series: pd.Series, column_name: str) -> List[str]:
        """Validate datetime column format."""
        issues = []
        non_null_values = series.dropna()
        
        if len(non_null_values) == 0:
            return issues
        
        # Try to parse datetimes
        try:
            parsed_datetimes = pd.to_datetime(non_null_values, errors='coerce')
            invalid_datetimes = parsed_datetimes.isna().sum()
            
            if invalid_datetimes > 0:
                issues.append(f"{invalid_datetimes} invalid datetime values found")
            
            # Check datetime ranges
            valid_datetimes = parsed_datetimes.dropna()
            if len(valid_datetimes) > 0:
                min_datetime = valid_datetimes.min()
                max_datetime = valid_datetimes.max()
                current_datetime = datetime.now()
                
                if min_datetime < datetime(1990, 1, 1):
                    issues.append(f"Datetime values too old (minimum: {min_datetime})")
                if max_datetime > current_datetime + timedelta(days=7):
                    issues.append(f"Datetime values too far in future (maximum: {max_datetime})")
        
        except Exception as e:
            issues.append(f"Failed to parse datetimes: {str(e)}")
        
        return issues
    
    def _validate_integer_column(self, series: pd.Series, column_name: str) -> List[str]:
        """Validate integer column values."""
        issues = []
        non_null_values = series.dropna()
        
        if len(non_null_values) == 0:
            return issues
        
        # Try to convert to numeric
        try:
            numeric_values = pd.to_numeric(non_null_values, errors='coerce')
            invalid_numbers = numeric_values.isna().sum()
            
            if invalid_numbers > 0:
                issues.append(f"{invalid_numbers} non-numeric values found")
            
            # Check if values are integers
            valid_numbers = numeric_values.dropna()
            if len(valid_numbers) > 0:
                non_integer_count = (valid_numbers != valid_numbers.astype(int)).sum()
                if non_integer_count > 0:
                    issues.append(f"{non_integer_count} non-integer values found")
                
                # Range checks for year column
                if column_name == "ano":
                    min_year = valid_numbers.min()
                    max_year = valid_numbers.max()
                    current_year = datetime.now().year
                    
                    if min_year < 1800:
                        issues.append(f"Year values too old (minimum: {min_year})")
                    if max_year > current_year + 1:
                        issues.append(f"Year values in future (maximum: {max_year})")
        
        except Exception as e:
            issues.append(f"Failed to validate integer values: {str(e)}")
        
        return issues
    
    def _validate_categorical_column(self, series: pd.Series, column_name: str) -> List[str]:
        """Validate categorical column values."""
        issues = []
        
        if column_name not in self.categorical_values:
            return issues
        
        expected_values = set(self.categorical_values[column_name])
        actual_values = set(series.dropna().astype(str))
        
        # Find unexpected values
        unexpected_values = actual_values - expected_values
        if unexpected_values:
            issues.append(f"Unexpected categorical values: {list(unexpected_values)}")
        
        return issues
    
    def calculate_data_completeness(self, file_path: Path) -> Dict[str, Any]:
        """
        Calculate data completeness metrics for each column.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Dictionary containing completeness metrics
        """
        result = {
            "file_name": file_path.name,
            "total_rows": 0,
            "column_completeness": {},
            "overall_completeness": 0.0,
            "completeness_issues": []
        }
        
        try:
            df = pd.read_csv(file_path, encoding=self.detect_file_encoding(file_path), low_memory=False)
            result["total_rows"] = len(df)
            
            if len(df) == 0:
                result["completeness_issues"].append("File is empty")
                return result
            
            # Calculate completeness for each column
            for column in df.columns:
                non_null_count = df[column].notna().sum()
                completeness_rate = (non_null_count / len(df)) * 100
                result["column_completeness"][column] = {
                    "non_null_count": int(non_null_count),
                    "null_count": int(len(df) - non_null_count),
                    "completeness_percentage": round(completeness_rate, 2)
                }
                
                # Flag low completeness columns
                if completeness_rate < 50:
                    result["completeness_issues"].append(f"Column '{column}' has low completeness: {completeness_rate:.1f}%")
            
            # Calculate overall completeness
            total_cells = len(df) * len(df.columns)
            non_null_cells = df.notna().sum().sum()
            result["overall_completeness"] = round((non_null_cells / total_cells) * 100, 2)
            
            logger.info(f"Completeness analysis for {file_path.name}: {result['overall_completeness']:.1f}% complete")
            
        except Exception as e:
            result["completeness_issues"].append(f"Failed to calculate completeness: {str(e)}")
            logger.error(f"Failed to calculate completeness for {file_path}: {e}")
        
        return result
    
    def analyze_data_consistency(self) -> Dict[str, Any]:
        """
        Analyze data consistency across all cleaned files.
        
        Returns:
            Dictionary containing consistency analysis results
        """
        result = {
            "cross_file_consistency": {},
            "schema_consistency": True,
            "categorical_consistency": {},
            "consistency_issues": []
        }
        
        try:
            schemas = []
            categorical_values_by_file = {}
            
            for file_path in self.cleaned_files:
                try:
                    df = pd.read_csv(file_path, encoding=self.detect_file_encoding(file_path), nrows=1)
                    schemas.append(list(df.columns))
                    
                    # Collect categorical values from each file
                    df_full = pd.read_csv(file_path, encoding=self.detect_file_encoding(file_path), low_memory=False)
                    file_categorical = {}
                    for column in self.categorical_values.keys():
                        if column in df_full.columns:
                            unique_values = set(df_full[column].dropna().astype(str))
                            file_categorical[column] = unique_values
                    
                    categorical_values_by_file[file_path.name] = file_categorical
                    
                except Exception as e:
                    result["consistency_issues"].append(f"Failed to analyze {file_path.name}: {str(e)}")
                    continue
            
            # Check schema consistency
            if schemas:
                first_schema = schemas[0]
                for i, schema in enumerate(schemas[1:], 1):
                    if schema != first_schema:
                        result["schema_consistency"] = False
                        result["consistency_issues"].append(f"Schema mismatch in file {i+1}")
            
            # Check categorical value consistency
            for column in self.categorical_values.keys():
                all_values = set()
                for file_values in categorical_values_by_file.values():
                    if column in file_values:
                        all_values.update(file_values[column])
                
                expected_values = set(self.categorical_values[column])
                unexpected_values = all_values - expected_values
                
                result["categorical_consistency"][column] = {
                    "expected_values": list(expected_values),
                    "found_values": list(all_values),
                    "unexpected_values": list(unexpected_values),
                    "is_consistent": len(unexpected_values) == 0
                }
                
                if unexpected_values:
                    result["consistency_issues"].append(f"Unexpected values in {column}: {list(unexpected_values)}")
            
            logger.info(f"Consistency analysis completed across {len(self.cleaned_files)} files")
            
        except Exception as e:
            result["consistency_issues"].append(f"Failed to analyze consistency: {str(e)}")
            logger.error(f"Failed to analyze data consistency: {e}")
        
        return result
    
    def generate_summary_statistics(self, file_path: Path) -> Dict[str, Any]:
        """
        Generate summary statistics for numerical and categorical columns.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Dictionary containing summary statistics
        """
        result = {
            "file_name": file_path.name,
            "numerical_stats": {},
            "categorical_stats": {},
            "text_stats": {},
            "statistics_issues": []
        }
        
        try:
            df = pd.read_csv(file_path, encoding=self.detect_file_encoding(file_path), low_memory=False)
            
            # Numerical statistics
            for column in df.columns:
                if column in ["ano"]:  # Known numerical columns
                    try:
                        numeric_series = pd.to_numeric(df[column], errors='coerce')
                        if not numeric_series.isna().all():
                            result["numerical_stats"][column] = {
                                "count": int(numeric_series.count()),
                                "mean": round(numeric_series.mean(), 2),
                                "std": round(numeric_series.std(), 2),
                                "min": int(numeric_series.min()),
                                "25%": int(numeric_series.quantile(0.25)),
                                "50%": int(numeric_series.median()),
                                "75%": int(numeric_series.quantile(0.75)),
                                "max": int(numeric_series.max())
                            }
                    except Exception as e:
                        result["statistics_issues"].append(f"Failed to calculate stats for {column}: {str(e)}")
            
            # Categorical statistics
            for column in self.categorical_values.keys():
                if column in df.columns:
                    try:
                        value_counts = df[column].value_counts(dropna=False)
                        result["categorical_stats"][column] = {
                            "unique_count": len(value_counts),
                            "most_common": value_counts.head().to_dict(),
                            "null_count": int(df[column].isna().sum())
                        }
                    except Exception as e:
                        result["statistics_issues"].append(f"Failed to calculate categorical stats for {column}: {str(e)}")
            
            # Text statistics for key text columns
            for column in ["titulo", "ementa", "assuntos"]:
                if column in df.columns:
                    try:
                        text_series = df[column].dropna().astype(str)
                        if len(text_series) > 0:
                            lengths = text_series.str.len()
                            result["text_stats"][column] = {
                                "count": len(text_series),
                                "avg_length": round(lengths.mean(), 2),
                                "min_length": int(lengths.min()),
                                "max_length": int(lengths.max()),
                                "empty_strings": int((text_series == "").sum())
                            }
                    except Exception as e:
                        result["statistics_issues"].append(f"Failed to calculate text stats for {column}: {str(e)}")
            
            logger.info(f"Summary statistics generated for {file_path.name}")
            
        except Exception as e:
            result["statistics_issues"].append(f"Failed to generate statistics: {str(e)}")
            logger.error(f"Failed to generate statistics for {file_path}: {e}")
        
        return result
    
    def run_comprehensive_validation(self) -> Dict[str, Any]:
        """
        Run all validation checks on all cleaned CSV files.
        
        Returns:
            Dictionary containing comprehensive validation results
        """
        logger.info("Starting comprehensive data validation...")
        
        validation_summary = {
            "validation_timestamp": self.validation_timestamp.isoformat(),
            "total_files": len(self.cleaned_files),
            "files_processed": 0,
            "files_with_issues": 0,
            "validation_results": {},
            "cross_file_analysis": {},
            "overall_health_score": 0.0,
            "recommendations": []
        }
        
        # Process each file
        for file_path in self.cleaned_files:
            logger.info(f"Processing {file_path.name}...")
            
            file_results = {
                "structure": self.validate_csv_structure(file_path),
                "schema": self.validate_schema_consistency(file_path),
                "data_types": self.validate_data_types(file_path),
                "completeness": self.calculate_data_completeness(file_path),
                "statistics": self.generate_summary_statistics(file_path)
            }
            
            validation_summary["validation_results"][file_path.name] = file_results
            validation_summary["files_processed"] += 1
            
            # Check if file has issues
            has_issues = (
                len(file_results["structure"]["structural_issues"]) > 0 or
                not file_results["schema"]["schema_valid"] or
                not file_results["data_types"]["type_validation_passed"] or
                len(file_results["completeness"]["completeness_issues"]) > 0
            )
            
            if has_issues:
                validation_summary["files_with_issues"] += 1
        
        # Cross-file analysis
        validation_summary["cross_file_analysis"]["consistency"] = self.analyze_data_consistency()
        
        # Calculate overall health score
        files_without_issues = validation_summary["files_processed"] - validation_summary["files_with_issues"]
        if validation_summary["files_processed"] > 0:
            validation_summary["overall_health_score"] = round(
                (files_without_issues / validation_summary["files_processed"]) * 100, 2
            )
        
        # Generate recommendations
        validation_summary["recommendations"] = self._generate_recommendations(validation_summary)
        
        logger.info(f"Comprehensive validation completed. Health score: {validation_summary['overall_health_score']:.1f}%")
        
        return validation_summary
    
    def _generate_recommendations(self, validation_summary: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []
        
        # Check for common issues across files
        schema_issues = 0
        type_issues = 0
        completeness_issues = 0
        
        for file_results in validation_summary["validation_results"].values():
            if not file_results["schema"]["schema_valid"]:
                schema_issues += 1
            if not file_results["data_types"]["type_validation_passed"]:
                type_issues += 1
            if len(file_results["completeness"]["completeness_issues"]) > 0:
                completeness_issues += 1
        
        total_files = validation_summary["files_processed"]
        
        if schema_issues > 0:
            recommendations.append(f"Schema inconsistencies found in {schema_issues}/{total_files} files. Review column names and order.")
        
        if type_issues > 0:
            recommendations.append(f"Data type issues found in {type_issues}/{total_files} files. Consider data type conversion and validation.")
        
        if completeness_issues > 0:
            recommendations.append(f"Data completeness issues found in {completeness_issues}/{total_files} files. Review missing data patterns.")
        
        # Cross-file consistency recommendations
        consistency_result = validation_summary["cross_file_analysis"]["consistency"]
        if not consistency_result["schema_consistency"]:
            recommendations.append("Schema inconsistency across files detected. Standardize column names and order.")
        
        if len(consistency_result["consistency_issues"]) > 0:
            recommendations.append("Categorical value inconsistencies found across files. Standardize categorical values.")
        
        # Overall health recommendations
        health_score = validation_summary["overall_health_score"]
        if health_score < 80:
            recommendations.append("Overall data health score is below 80%. Consider comprehensive data cleaning.")
        elif health_score < 90:
            recommendations.append("Data quality is good but could be improved. Address specific issues identified.")
        else:
            recommendations.append("Excellent data quality! Maintain current data standards.")
        
        return recommendations
    
    def save_validation_report(self, validation_results: Dict[str, Any], output_file: str = None) -> str:
        """
        Save validation results to a JSON file.
        
        Args:
            validation_results: Results from comprehensive validation
            output_file: Output file path (optional)
            
        Returns:
            Path to the saved report file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.data_directory / f"comprehensive_validation_report_{timestamp}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(validation_results, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Validation report saved to {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to save validation report: {e}")
            return ""

def main():
    """Main execution function."""
    # Get the current directory
    current_dir = os.getcwd()
    
    # Initialize validator
    validator = ComprehensiveDataValidator(current_dir)
    
    # Run comprehensive validation
    validation_results = validator.run_comprehensive_validation()
    
    # Save validation report
    report_file = validator.save_validation_report(validation_results)
    
    # Print summary
    print("\n" + "="*80)
    print("COMPREHENSIVE DATA VALIDATION SUMMARY")
    print("="*80)
    print(f"Files processed: {validation_results['files_processed']}")
    print(f"Files with issues: {validation_results['files_with_issues']}")
    print(f"Overall health score: {validation_results['overall_health_score']:.1f}%")
    print(f"Report saved to: {report_file}")
    print("\nRecommendations:")
    for i, rec in enumerate(validation_results['recommendations'], 1):
        print(f"{i}. {rec}")
    print("="*80)

if __name__ == "__main__":
    main()