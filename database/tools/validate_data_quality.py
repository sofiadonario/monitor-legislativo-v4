#!/usr/bin/env python3
"""
Data Quality Validation for Brazilian Legislative Documents
============================================================

Purpose: Automated validation of 134k+ legislative documents
Features:
- UTF-8 encoding verification
- Portuguese diacritics detection
- Data completeness checks
- URN uniqueness validation
- Date format validation
- Estado (state) consistency checks
- HTML report generation

Author: DevOps Engineering Team
Date: 2025-11-09
"""

import sys
import os
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq
from datetime import datetime
import argparse
import re
from typing import Dict, List, Tuple
from collections import Counter
import warnings

warnings.filterwarnings('ignore')

# Project paths
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent


class DataQualityValidator:
    """Comprehensive data quality validation for legislative documents"""

    def __init__(self, data_path: Path):
        self.data_path = data_path
        self.df = None
        self.validation_results = {}
        self.errors = []
        self.warnings = []

    def load_data(self) -> bool:
        """Load data from Parquet or CSV"""
        print(f"📂 Loading data from {self.data_path}...")

        try:
            if str(self.data_path).endswith('.parquet'):
                self.df = pd.read_parquet(self.data_path)
            elif str(self.data_path).endswith('.csv'):
                self.df = pd.read_csv(self.data_path, encoding='utf-8')
            else:
                print(f"❌ Unsupported file format: {self.data_path}")
                return False

            print(f"✅ Loaded {len(self.df):,} rows × {len(self.df.columns)} columns")
            return True

        except Exception as e:
            print(f"❌ Failed to load data: {e}")
            return False

    def validate_encoding(self) -> Dict:
        """Validate UTF-8 encoding and Portuguese characters"""
        print("\n🔍 Validating UTF-8 encoding...")

        results = {
            'test': 'UTF-8 Encoding',
            'status': 'PASS',
            'issues': []
        }

        # Portuguese diacritics to check
        portuguese_chars = {
            'ã': 'til (a)',
            'õ': 'til (o)',
            'ç': 'cedilha',
            'é': 'acento agudo (e)',
            'ê': 'acento circunflexo (e)',
            'á': 'acento agudo (a)',
            'à': 'acento grave (a)',
            'ó': 'acento agudo (o)',
            'ô': 'acento circunflexo (o)',
            'í': 'acento agudo (i)',
            'ú': 'acento agudo (u)'
        }

        # Check text columns
        text_columns = ['titulo', 'content', 'ementa', 'municipio', 'autor']
        found_chars = set()

        for col in text_columns:
            if col not in self.df.columns:
                continue

            # Sample text
            sample_text = ' '.join(self.df[col].dropna().astype(str).head(1000))

            for char, name in portuguese_chars.items():
                if char in sample_text:
                    found_chars.add(f"{char} ({name})")

        if found_chars:
            results['portuguese_chars_found'] = sorted(list(found_chars))
            print(f"   ✅ Found Portuguese diacritics: {', '.join(sorted(found_chars))}")
        else:
            results['status'] = 'WARNING'
            results['issues'].append('No Portuguese diacritics found in sample')
            self.warnings.append('No Portuguese diacritics detected - check encoding')

        self.validation_results['encoding'] = results
        return results

    def validate_completeness(self) -> Dict:
        """Validate data completeness for critical fields"""
        print("\n🔍 Validating data completeness...")

        critical_fields = {
            'titulo': 0.95,      # 95% required
            'urn': 0.90,         # 90% required
            'data': 0.95,        # 95% required (or data_publicacao)
            'tipo': 0.90,        # 90% required
            'estado': 0.70,      # 70% required (many are federal)
        }

        results = {
            'test': 'Data Completeness',
            'status': 'PASS',
            'field_completeness': {},
            'issues': []
        }

        total_rows = len(self.df)

        for field, threshold in critical_fields.items():
            # Handle alternative column names
            if field == 'data' and 'data' not in self.df.columns:
                field = 'data_publicacao'

            if field == 'content' and 'content' not in self.df.columns:
                field = 'ementa'

            if field not in self.df.columns:
                results['field_completeness'][field] = {
                    'completeness': 0.0,
                    'status': 'MISSING'
                }
                results['status'] = 'WARNING'
                self.warnings.append(f"Field '{field}' not found in dataset")
                continue

            # Calculate completeness
            non_null = self.df[field].notna().sum()
            non_empty = (self.df[field].astype(str).str.strip() != '').sum() if non_null > 0 else 0
            completeness = non_empty / total_rows

            status = 'PASS' if completeness >= threshold else 'FAIL'

            results['field_completeness'][field] = {
                'total': total_rows,
                'filled': non_empty,
                'completeness': round(completeness * 100, 2),
                'threshold': round(threshold * 100, 2),
                'status': status
            }

            if status == 'FAIL':
                results['status'] = 'FAIL'
                msg = f"Field '{field}': {completeness*100:.1f}% complete (threshold: {threshold*100:.1f}%)"
                results['issues'].append(msg)
                self.errors.append(msg)
                print(f"   ❌ {msg}")
            else:
                print(f"   ✅ {field}: {completeness*100:.1f}% complete")

        self.validation_results['completeness'] = results
        return results

    def validate_urn_uniqueness(self) -> Dict:
        """Validate URN uniqueness (critical for deduplication)"""
        print("\n🔍 Validating URN uniqueness...")

        results = {
            'test': 'URN Uniqueness',
            'status': 'PASS',
            'issues': []
        }

        # Check if URN column exists
        urn_col = 'urn' if 'urn' in self.df.columns else None

        if not urn_col:
            results['status'] = 'WARNING'
            results['issues'].append('URN column not found')
            self.warnings.append('URN column not found in dataset')
            self.validation_results['urn_uniqueness'] = results
            return results

        # Filter non-empty URNs
        urns = self.df[urn_col].dropna()
        urns = urns[urns.astype(str).str.strip() != '']

        total_urns = len(urns)
        unique_urns = urns.nunique()
        duplicates = total_urns - unique_urns

        results['total_urns'] = total_urns
        results['unique_urns'] = unique_urns
        results['duplicates'] = duplicates
        results['uniqueness_rate'] = round((unique_urns / total_urns * 100), 2) if total_urns > 0 else 0

        if duplicates > 0:
            results['status'] = 'FAIL'
            msg = f"Found {duplicates:,} duplicate URNs ({duplicates/total_urns*100:.2f}%)"
            results['issues'].append(msg)
            self.errors.append(msg)
            print(f"   ❌ {msg}")

            # Show top duplicates
            duplicate_urns = urns[urns.duplicated(keep=False)].value_counts().head(5)
            results['top_duplicates'] = duplicate_urns.to_dict()
            print(f"   Top duplicates:")
            for urn, count in duplicate_urns.items():
                print(f"     - {urn[:80]}... ({count} occurrences)")
        else:
            print(f"   ✅ All {unique_urns:,} URNs are unique")

        self.validation_results['urn_uniqueness'] = results
        return results

    def validate_dates(self) -> Dict:
        """Validate date fields"""
        print("\n🔍 Validating date fields...")

        results = {
            'test': 'Date Validation',
            'status': 'PASS',
            'issues': []
        }

        # Find date column
        date_col = None
        for col in ['data_publicacao', 'data']:
            if col in self.df.columns:
                date_col = col
                break

        if not date_col:
            results['status'] = 'WARNING'
            results['issues'].append('No date column found')
            self.warnings.append('No date column found in dataset')
            self.validation_results['dates'] = results
            return results

        # Try to parse dates
        try:
            dates = pd.to_datetime(self.df[date_col], errors='coerce')
            valid_dates = dates.notna().sum()
            total_dates = len(self.df[date_col].dropna())
            validity_rate = (valid_dates / total_dates * 100) if total_dates > 0 else 0

            results['total_dates'] = total_dates
            results['valid_dates'] = valid_dates
            results['validity_rate'] = round(validity_rate, 2)

            if validity_rate < 95:
                results['status'] = 'FAIL'
                msg = f"Only {validity_rate:.1f}% of dates are valid"
                results['issues'].append(msg)
                self.errors.append(msg)
                print(f"   ❌ {msg}")
            else:
                print(f"   ✅ {validity_rate:.1f}% of dates are valid")

            # Check date range
            if valid_dates > 0:
                min_date = dates.min()
                max_date = dates.max()
                results['date_range'] = {
                    'min': str(min_date)[:10],
                    'max': str(max_date)[:10]
                }
                print(f"   📅 Date range: {min_date:%Y-%m-%d} to {max_date:%Y-%m-%d}")

                # Validate reasonable range (1829-2025)
                if min_date.year < 1829 or max_date.year > 2025:
                    results['status'] = 'WARNING'
                    msg = f"Date range outside expected bounds (1829-2025)"
                    results['issues'].append(msg)
                    self.warnings.append(msg)
                    print(f"   ⚠️  {msg}")

        except Exception as e:
            results['status'] = 'FAIL'
            msg = f"Date parsing failed: {e}"
            results['issues'].append(msg)
            self.errors.append(msg)
            print(f"   ❌ {msg}")

        self.validation_results['dates'] = results
        return results

    def validate_estado(self) -> Dict:
        """Validate estado (state) field consistency"""
        print("\n🔍 Validating estado field...")

        results = {
            'test': 'Estado Field Validation',
            'status': 'PASS',
            'issues': []
        }

        if 'estado' not in self.df.columns:
            results['status'] = 'WARNING'
            results['issues'].append('Estado column not found')
            self.validation_results['estado'] = results
            return results

        # Valid Brazilian state codes
        valid_states = {
            'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO',
            'MA', 'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI',
            'RJ', 'RN', 'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO'
        }

        # Get estado distribution
        estados = self.df['estado'].dropna()
        estados = estados[estados.astype(str).str.strip() != '']

        # Check for 'Federal' (should be 'DF')
        federal_count = (estados.str.upper() == 'FEDERAL').sum()
        if federal_count > 0:
            results['status'] = 'FAIL'
            msg = f"Found {federal_count:,} 'Federal' values (should be 'DF')"
            results['issues'].append(msg)
            self.errors.append(msg)
            print(f"   ❌ {msg}")

        # Check for invalid state codes
        invalid_estados = estados[~estados.str.upper().isin(valid_states)]
        if len(invalid_estados) > 0:
            results['status'] = 'FAIL'
            invalid_counts = invalid_estados.value_counts().head(10)
            msg = f"Found {len(invalid_estados):,} invalid estado values"
            results['issues'].append(msg)
            results['invalid_estados'] = invalid_counts.to_dict()
            self.errors.append(msg)
            print(f"   ❌ {msg}")
            print(f"   Top invalid values:")
            for estado, count in invalid_counts.items():
                print(f"     - '{estado}': {count:,} occurrences")
        else:
            print(f"   ✅ All estado values are valid")

        # Estado distribution
        estado_dist = estados.str.upper().value_counts()
        results['estado_distribution'] = estado_dist.head(10).to_dict()

        self.validation_results['estado'] = results
        return results

    def validate_portuguese_text(self) -> Dict:
        """Validate Portuguese text quality"""
        print("\n🔍 Validating Portuguese text quality...")

        results = {
            'test': 'Portuguese Text Quality',
            'status': 'PASS',
            'issues': []
        }

        # Common Portuguese legal terms
        legal_terms = [
            'lei', 'decreto', 'portaria', 'resolução', 'artigo',
            'parágrafo', 'inciso', 'público', 'federal', 'estadual',
            'municipal', 'transporte', 'legislação'
        ]

        text_columns = ['titulo', 'content', 'ementa']
        found_terms = {}

        for col in text_columns:
            if col not in self.df.columns:
                continue

            # Sample text
            sample = self.df[col].dropna().head(100)
            text = ' '.join(sample.astype(str).str.lower())

            # Count legal terms
            term_counts = {}
            for term in legal_terms:
                count = text.count(term)
                if count > 0:
                    term_counts[term] = count

            found_terms[col] = term_counts

        # Check if we found legal terms
        total_terms = sum(sum(counts.values()) for counts in found_terms.values())

        if total_terms == 0:
            results['status'] = 'WARNING'
            msg = "No common legal terms found in text sample"
            results['issues'].append(msg)
            self.warnings.append(msg)
            print(f"   ⚠️  {msg}")
        else:
            results['legal_terms_found'] = found_terms
            print(f"   ✅ Found {total_terms} instances of common legal terms")

        self.validation_results['portuguese_text'] = results
        return results

    def generate_report(self, output_path: Path = None):
        """Generate validation report"""
        if output_path is None:
            output_path = PROJECT_ROOT / 'reports' / f'data_quality_report_{datetime.now():%Y%m%d_%H%M%S}.txt'

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("DATA QUALITY VALIDATION REPORT\n")
            f.write("Monitor Legislativo v4 - Brazilian Legislative Documents\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Validation Date: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Dataset: {self.data_path}\n")
            f.write(f"Total Records: {len(self.df):,}\n")
            f.write(f"Total Columns: {len(self.df.columns)}\n\n")

            # Overall status
            has_errors = len(self.errors) > 0
            has_warnings = len(self.warnings) > 0

            if has_errors:
                overall_status = "FAILED"
            elif has_warnings:
                overall_status = "PASSED WITH WARNINGS"
            else:
                overall_status = "PASSED"

            f.write(f"Overall Status: {overall_status}\n")
            f.write(f"Errors: {len(self.errors)}\n")
            f.write(f"Warnings: {len(self.warnings)}\n\n")

            # Detailed results
            f.write("=" * 80 + "\n")
            f.write("DETAILED VALIDATION RESULTS\n")
            f.write("=" * 80 + "\n\n")

            for test_name, result in self.validation_results.items():
                f.write(f"\n{result['test']}\n")
                f.write("-" * 40 + "\n")
                f.write(f"Status: {result['status']}\n")

                if 'issues' in result and result['issues']:
                    f.write("Issues:\n")
                    for issue in result['issues']:
                        f.write(f"  - {issue}\n")

                # Additional details
                for key, value in result.items():
                    if key not in ['test', 'status', 'issues']:
                        if isinstance(value, dict):
                            f.write(f"{key}:\n")
                            for k, v in value.items():
                                f.write(f"  {k}: {v}\n")
                        elif isinstance(value, (list, tuple)):
                            f.write(f"{key}: {', '.join(map(str, value))}\n")
                        else:
                            f.write(f"{key}: {value}\n")

            # Summary
            f.write("\n" + "=" * 80 + "\n")
            f.write("SUMMARY\n")
            f.write("=" * 80 + "\n\n")

            if self.errors:
                f.write("ERRORS:\n")
                for i, error in enumerate(self.errors, 1):
                    f.write(f"{i}. {error}\n")
                f.write("\n")

            if self.warnings:
                f.write("WARNINGS:\n")
                for i, warning in enumerate(self.warnings, 1):
                    f.write(f"{i}. {warning}\n")
                f.write("\n")

            if not has_errors and not has_warnings:
                f.write("✅ All validation checks passed!\n")
                f.write("   Data quality is excellent and ready for production use.\n")

            f.write("\n" + "=" * 80 + "\n")

        print(f"\n📄 Report saved to: {output_path}")
        return output_path

    def run_all_validations(self) -> bool:
        """Run all validation tests"""
        print("\n" + "=" * 80)
        print("RUNNING DATA QUALITY VALIDATION")
        print("=" * 80)

        # Load data
        if not self.load_data():
            return False

        # Run all validations
        self.validate_encoding()
        self.validate_completeness()
        self.validate_urn_uniqueness()
        self.validate_dates()
        self.validate_estado()
        self.validate_portuguese_text()

        # Summary
        print("\n" + "=" * 80)
        print("VALIDATION SUMMARY")
        print("=" * 80)

        total_tests = len(self.validation_results)
        passed = sum(1 for r in self.validation_results.values() if r['status'] == 'PASS')
        warnings = sum(1 for r in self.validation_results.values() if r['status'] == 'WARNING')
        failed = sum(1 for r in self.validation_results.values() if r['status'] == 'FAIL')

        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed} ✅")
        print(f"Warnings: {warnings} ⚠️")
        print(f"Failed: {failed} ❌")
        print()

        if failed == 0 and warnings == 0:
            print("✅ ALL CHECKS PASSED - Data quality is excellent!")
            return True
        elif failed == 0:
            print("⚠️  PASSED WITH WARNINGS - Review warnings before production")
            return True
        else:
            print("❌ VALIDATION FAILED - Fix errors before using data")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Validate data quality for Brazilian legislative documents'
    )

    parser.add_argument(
        '--input', '-i',
        type=Path,
        default=PROJECT_ROOT / 'data_current/processed/production/parquet/single_file/brazilian_legislative_complete.parquet',
        help='Input data file (Parquet or CSV)'
    )

    parser.add_argument(
        '--report-path', '-r',
        type=Path,
        help='Output report path (default: auto-generated in reports/)'
    )

    args = parser.parse_args()

    # Create validator
    validator = DataQualityValidator(args.input)

    # Run validations
    success = validator.run_all_validations()

    # Generate report
    validator.generate_report(args.report_path)

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
