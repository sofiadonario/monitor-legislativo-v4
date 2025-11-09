#!/usr/bin/env python3
"""
Parquet to CSV Converter for Brazilian Legislative Documents
==============================================================

Purpose: Generate CSV file from Parquet to fix documentation mismatch
Input: Parquet file (brazilian_legislative_complete.parquet)
Output: CSV file (lexml_unified_dataset.csv)

This script addresses the critical issue where documentation references
a CSV file that doesn't exist, causing script failures.

Features:
- UTF-8 encoding preservation for Portuguese diacritics
- Memory-efficient chunked processing for large datasets
- Data validation and quality checks
- Progress reporting
- Automatic column mapping

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
from typing import Optional

# Add project root to path
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class ParquetToCSVConverter:
    """Convert Parquet files to CSV with Portuguese encoding support"""

    def __init__(self, parquet_path: Path, csv_path: Path, chunk_size: int = 10000):
        self.parquet_path = parquet_path
        self.csv_path = csv_path
        self.chunk_size = chunk_size
        self.total_rows = 0
        self.processed_rows = 0

    def validate_parquet(self) -> bool:
        """Validate input Parquet file exists and is readable"""
        if not self.parquet_path.exists():
            print(f"❌ Error: Parquet file not found: {self.parquet_path}")
            return False

        try:
            # Try to read schema
            parquet_file = pq.ParquetFile(self.parquet_path)
            self.total_rows = parquet_file.metadata.num_rows
            print(f"✅ Parquet file valid: {self.total_rows:,} rows")
            return True
        except Exception as e:
            print(f"❌ Error reading Parquet file: {e}")
            return False

    def map_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Map Parquet columns to expected CSV schema

        Parquet schema -> CSV schema mapping:
        - data -> data_publicacao (convert to date)
        - ano -> ano (convert to integer)
        - ementa -> content (rename for database compatibility)
        - autoridade -> orgao_emissor (if autor is empty)
        """
        # Create copy to avoid modifying original
        mapped_df = df.copy()

        # Rename columns for database compatibility
        column_mapping = {}

        if 'data' in mapped_df.columns and 'data_publicacao' not in mapped_df.columns:
            column_mapping['data'] = 'data_publicacao'

        if 'ementa' in mapped_df.columns and 'content' not in mapped_df.columns:
            column_mapping['ementa'] = 'content'

        if 'autoridade' in mapped_df.columns and 'orgao_emissor' not in mapped_df.columns:
            # Use autoridade if autor is empty
            if 'autor' in mapped_df.columns:
                mapped_df['orgao_emissor'] = mapped_df['autor'].fillna(mapped_df['autoridade'])
            else:
                column_mapping['autoridade'] = 'orgao_emissor'

        # Apply renaming
        if column_mapping:
            mapped_df = mapped_df.rename(columns=column_mapping)
            print(f"📝 Mapped columns: {column_mapping}")

        # Convert data types
        if 'data_publicacao' in mapped_df.columns:
            try:
                mapped_df['data_publicacao'] = pd.to_datetime(
                    mapped_df['data_publicacao'], errors='coerce'
                ).dt.strftime('%Y-%m-%d')
            except Exception as e:
                print(f"⚠️  Warning: Date conversion failed: {e}")

        if 'ano' in mapped_df.columns:
            try:
                mapped_df['ano'] = pd.to_numeric(mapped_df['ano'], errors='coerce').astype('Int64')
            except Exception as e:
                print(f"⚠️  Warning: Year conversion failed: {e}")

        return mapped_df

    def convert_chunked(self, validate_encoding: bool = True) -> bool:
        """
        Convert Parquet to CSV using chunked processing for memory efficiency

        Args:
            validate_encoding: Check Portuguese diacritics are preserved

        Returns:
            True if conversion successful, False otherwise
        """
        print(f"\n🔄 Converting Parquet to CSV...")
        print(f"   Input:  {self.parquet_path}")
        print(f"   Output: {self.csv_path}")
        print(f"   Chunk size: {self.chunk_size:,} rows")
        print()

        try:
            # Create output directory if needed
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)

            # Open Parquet file for reading
            parquet_file = pq.ParquetFile(self.parquet_path)

            # Process in chunks
            first_chunk = True
            chunks_processed = 0

            for batch in parquet_file.iter_batches(batch_size=self.chunk_size):
                # Convert Arrow batch to Pandas DataFrame
                chunk_df = batch.to_pandas()

                # Map columns
                chunk_df = self.map_columns(chunk_df)

                # Write to CSV
                chunk_df.to_csv(
                    self.csv_path,
                    mode='w' if first_chunk else 'a',
                    header=first_chunk,
                    index=False,
                    encoding='utf-8',
                    na_rep='',  # Represent NA as empty string
                    escapechar='\\',
                    quotechar='"',
                    quoting=1  # QUOTE_MINIMAL
                )

                chunks_processed += 1
                self.processed_rows += len(chunk_df)
                progress = (self.processed_rows / self.total_rows) * 100

                print(f"   Progress: {self.processed_rows:,} / {self.total_rows:,} "
                      f"({progress:.1f}%) - Chunk {chunks_processed}", end='\r')

                first_chunk = False

            print()  # New line after progress
            print(f"✅ Conversion complete: {self.processed_rows:,} rows written")

            # Validate encoding if requested
            if validate_encoding:
                self.validate_encoding()

            return True

        except Exception as e:
            print(f"\n❌ Error during conversion: {e}")
            import traceback
            traceback.print_exc()
            return False

    def validate_encoding(self, sample_size: int = 100):
        """
        Validate Portuguese diacritics are preserved in CSV

        Checks for common Portuguese characters:
        ã, ç, é, ê, õ, ô, á, à, í, ó, ú
        """
        print(f"\n🔍 Validating UTF-8 encoding...")

        try:
            # Read sample from CSV
            sample_df = pd.read_csv(
                self.csv_path,
                encoding='utf-8',
                nrows=sample_size
            )

            # Check for Portuguese characters in text columns
            text_columns = ['titulo', 'content', 'municipio', 'orgao_emissor']
            portuguese_chars = set('ãçéêõôáàíóúâîûñ')

            found_diacritics = False
            for col in text_columns:
                if col in sample_df.columns:
                    text_sample = ' '.join(sample_df[col].dropna().astype(str))
                    if any(char in text_sample for char in portuguese_chars):
                        found_diacritics = True
                        print(f"   ✅ Portuguese diacritics found in {col}")

            if found_diacritics:
                print("✅ UTF-8 encoding validation passed")
            else:
                print("⚠️  Warning: No Portuguese diacritics found in sample")
                print("   (This might be normal if sample has no Portuguese text)")

        except Exception as e:
            print(f"⚠️  Warning: Encoding validation failed: {e}")

    def generate_summary(self) -> dict:
        """Generate conversion summary statistics"""
        try:
            # Get file sizes
            parquet_size = self.parquet_path.stat().st_size
            csv_size = self.csv_path.stat().st_size

            # Calculate compression ratio
            compression_ratio = (1 - (csv_size / parquet_size)) * 100 if parquet_size > 0 else 0

            summary = {
                'input_file': str(self.parquet_path),
                'output_file': str(self.csv_path),
                'total_rows': self.total_rows,
                'parquet_size_mb': parquet_size / (1024 * 1024),
                'csv_size_mb': csv_size / (1024 * 1024),
                'compression_ratio': compression_ratio,
                'timestamp': datetime.now().isoformat()
            }

            return summary

        except Exception as e:
            print(f"⚠️  Warning: Could not generate summary: {e}")
            return {}


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Convert Parquet file to CSV for Brazilian legislative documents',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert default production file
  python3 parquet_to_csv.py

  # Convert specific file
  python3 parquet_to_csv.py --input data/my_file.parquet --output data/my_file.csv

  # Use larger chunks for faster processing (more memory)
  python3 parquet_to_csv.py --chunk-size 50000

  # Skip encoding validation
  python3 parquet_to_csv.py --no-validate
        """
    )

    parser.add_argument(
        '--input', '-i',
        type=Path,
        default=PROJECT_ROOT / 'data_current/processed/production/parquet/single_file/brazilian_legislative_complete.parquet',
        help='Input Parquet file path'
    )

    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=PROJECT_ROOT / 'data_current/processed/production/lexml_unified_dataset.csv',
        help='Output CSV file path'
    )

    parser.add_argument(
        '--chunk-size', '-c',
        type=int,
        default=10000,
        help='Number of rows per chunk (default: 10000)'
    )

    parser.add_argument(
        '--no-validate',
        action='store_true',
        help='Skip UTF-8 encoding validation'
    )

    args = parser.parse_args()

    # Print header
    print("=" * 80)
    print("PARQUET TO CSV CONVERTER")
    print("Brazilian Legislative Documents - Monitor Legislativo v4")
    print("=" * 80)
    print()

    # Create converter
    converter = ParquetToCSVConverter(
        parquet_path=args.input,
        csv_path=args.output,
        chunk_size=args.chunk_size
    )

    # Validate input
    if not converter.validate_parquet():
        sys.exit(1)

    # Perform conversion
    success = converter.convert_chunked(validate_encoding=not args.no_validate)

    if not success:
        print("\n❌ Conversion failed!")
        sys.exit(1)

    # Generate summary
    print("\n" + "=" * 80)
    print("CONVERSION SUMMARY")
    print("=" * 80)

    summary = converter.generate_summary()
    if summary:
        print(f"Input:  {summary['input_file']}")
        print(f"Output: {summary['output_file']}")
        print(f"Rows:   {summary['total_rows']:,}")
        print(f"Parquet size: {summary['parquet_size_mb']:.2f} MB")
        print(f"CSV size:     {summary['csv_size_mb']:.2f} MB")
        print(f"Compression:  {summary['compression_ratio']:.1f}% (Parquet vs CSV)")
        print(f"Timestamp:    {summary['timestamp']}")

    print("\n✅ CSV file ready for use!")
    print(f"   Location: {args.output}")
    print("\nNext steps:")
    print("1. Update scripts to use CSV file")
    print("2. Test data loading with Portuguese characters")
    print("3. Consider keeping both formats (Parquet for performance, CSV for compatibility)")
    print("=" * 80)


if __name__ == '__main__':
    main()
