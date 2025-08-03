#!/usr/bin/env python3
"""
CSV Data Cleaner for Brazilian Legislative Data
Addresses critical data quality issues identified in CSV files.
"""

import pandas as pd
import os
import re
import csv
import logging
from typing import Dict, List, Tuple, Any
import json
from datetime import datetime
import chardet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('csv_cleaning.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CSVCleaner:
    """Comprehensive CSV cleaner for Brazilian legislative data."""
    
    def __init__(self, input_dir: str, output_suffix: str = "_cleaned"):
        self.input_dir = input_dir
        self.output_suffix = output_suffix
        self.cleaning_stats = {}
        self.total_processed = 0
        
    def detect_encoding(self, file_path: str) -> str:
        """Detect file encoding using chardet."""
        try:
            with open(file_path, 'rb') as file:
                raw_data = file.read(10000)  # Read first 10KB
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                confidence = result['confidence']
                logger.info(f"Detected encoding: {encoding} (confidence: {confidence:.2f})")
                return encoding if encoding else 'utf-8'
        except Exception as e:
            logger.warning(f"Encoding detection failed: {e}. Using UTF-8.")
            return 'utf-8'
    
    def clean_text_field(self, text: str) -> str:
        """Clean text fields by handling newlines and special characters."""
        if pd.isna(text) or text == '':
            return ''
        
        # Convert to string if not already
        text = str(text)
        
        # Replace embedded newlines with spaces
        text = re.sub(r'\r?\n', ' ', text)
        
        # Replace multiple spaces with single space
        text = re.sub(r'\s+', ' ', text)
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        # Escape quotes properly
        text = text.replace('"', '""')
        
        return text
    
    def validate_csv_structure(self, df: pd.DataFrame, filename: str) -> Dict[str, Any]:
        """Validate CSV structure and report issues."""
        stats = {
            'filename': filename,
            'total_rows': len(df),
            'total_columns': len(df.columns),
            'empty_columns': [],
            'missing_data_stats': {},
            'issues_found': [],
            'issues_fixed': []
        }
        
        # Check for completely empty columns
        for col in df.columns:
            if df[col].isna().all() or (df[col] == '').all():
                stats['empty_columns'].append(col)
        
        # Calculate missing data statistics
        for col in df.columns:
            missing_count = df[col].isna().sum() + (df[col] == '').sum()
            missing_percentage = (missing_count / len(df)) * 100
            stats['missing_data_stats'][col] = {
                'missing_count': int(missing_count),
                'missing_percentage': round(missing_percentage, 2)
            }
        
        return stats
    
    def fix_delimiter_issues(self, file_path: str, encoding: str) -> pd.DataFrame:
        """Fix delimiter and quote handling issues."""
        try:
            # First, try reading with pandas default settings
            df = pd.read_csv(
                file_path, 
                encoding=encoding,
                quoting=csv.QUOTE_ALL,
                escapechar='\\',
                on_bad_lines='skip'
            )
            logger.info(f"Successfully read {file_path} with {len(df)} rows")
            return df
            
        except Exception as e:
            logger.warning(f"Standard read failed for {file_path}: {e}")
            
            # Try with different parameters
            try:
                df = pd.read_csv(
                    file_path,
                    encoding=encoding,
                    sep=',',
                    quotechar='"',
                    quoting=csv.QUOTE_MINIMAL,
                    skipinitialspace=True,
                    on_bad_lines='skip',
                    engine='python'
                )
                logger.info(f"Alternative read successful for {file_path}")
                return df
                
            except Exception as e2:
                logger.error(f"All read attempts failed for {file_path}: {e2}")
                # Return empty DataFrame with error indication
                return pd.DataFrame()
    
    def clean_dataframe(self, df: pd.DataFrame, filename: str) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Clean DataFrame and return cleaning statistics."""
        if df.empty:
            return df, {'error': 'DataFrame is empty'}
        
        stats = self.validate_csv_structure(df, filename)
        original_rows = len(df)
        
        # Clean text fields that commonly have embedded newlines
        text_columns = ['assuntos', 'ementa', 'titulo', 'observacao']
        
        for col in text_columns:
            if col in df.columns:
                # Count rows with embedded newlines before cleaning
                newline_count = df[col].astype(str).str.contains(r'\r?\n', na=False).sum()
                if newline_count > 0:
                    stats['issues_found'].append(f"{col}: {newline_count} rows with embedded newlines")
                    
                # Clean the column
                df[col] = df[col].apply(self.clean_text_field)
                stats['issues_fixed'].append(f"{col}: cleaned {newline_count} embedded newlines")
        
        # Remove completely duplicate rows
        initial_rows = len(df)
        df = df.drop_duplicates()
        duplicates_removed = initial_rows - len(df)
        
        if duplicates_removed > 0:
            stats['issues_found'].append(f"Duplicate rows: {duplicates_removed}")
            stats['issues_fixed'].append(f"Removed {duplicates_removed} duplicate rows")
        
        # Standardize empty values
        df = df.fillna('')
        
        # Ensure data types are consistent
        for col in df.columns:
            if col in ['data', 'data_publicacao']:
                # Handle date columns - convert to consistent format if possible
                try:
                    df[col] = pd.to_datetime(df[col], errors='coerce').dt.strftime('%Y-%m-%d')
                    df[col] = df[col].fillna('')
                except:
                    pass
        
        stats['rows_after_cleaning'] = len(df)
        stats['rows_removed'] = original_rows - len(df)
        
        return df, stats
    
    def write_cleaned_csv(self, df: pd.DataFrame, output_path: str) -> bool:
        """Write cleaned DataFrame to CSV with proper formatting."""
        try:
            df.to_csv(
                output_path,
                index=False,
                encoding='utf-8',
                quoting=csv.QUOTE_ALL,
                quotechar='"',
                escapechar=None,
                lineterminator='\n'
            )
            logger.info(f"Successfully wrote cleaned file: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write {output_path}: {e}")
            return False
    
    def process_file(self, filename: str) -> Dict[str, Any]:
        """Process a single CSV file."""
        input_path = os.path.join(self.input_dir, filename)
        
        # Generate output filename
        name_parts = filename.rsplit('.', 1)
        output_filename = f"{name_parts[0]}{self.output_suffix}.{name_parts[1]}"
        output_path = os.path.join(self.input_dir, output_filename)
        
        logger.info(f"Processing: {filename}")
        
        # Detect encoding
        encoding = self.detect_encoding(input_path)
        
        # Read and fix delimiter issues
        df = self.fix_delimiter_issues(input_path, encoding)
        
        if df.empty:
            return {
                'filename': filename,
                'status': 'FAILED',
                'error': 'Could not read file or file is empty'
            }
        
        # Clean the data
        cleaned_df, stats = self.clean_dataframe(df, filename)
        
        # Write cleaned file
        success = self.write_cleaned_csv(cleaned_df, output_path)
        
        stats['status'] = 'SUCCESS' if success else 'FAILED'
        stats['output_file'] = output_filename
        stats['encoding_used'] = encoding
        
        return stats
    
    def get_file_processing_order(self) -> List[str]:
        """Get files ordered by priority (problematic files first)."""
        csv_files = [f for f in os.listdir(self.input_dir) if f.endswith('.csv') and not f.endswith('_cleaned.csv')]
        
        # Priority order based on analysis report
        priority_files = []
        medium_files = []
        low_files = []
        
        for filename in csv_files:
            if 'outros_rodoviário' in filename or 'outros_rodovi' in filename:
                priority_files.append(filename)  # Most problematic
            elif 'dataset_limpo_classificado' in filename:
                priority_files.append(filename)  # Largest file
            elif 'proposições' in filename or 'proposi' in filename:
                medium_files.append(filename)  # Missing data issues
            else:
                low_files.append(filename)
        
        # Sort within each group by file size (larger files first)
        def get_file_size(fname):
            try:
                return os.path.getsize(os.path.join(self.input_dir, fname))
            except:
                return 0
        
        priority_files.sort(key=get_file_size, reverse=True)
        medium_files.sort(key=get_file_size, reverse=True)
        low_files.sort(key=get_file_size, reverse=True)
        
        return priority_files + medium_files + low_files
    
    def process_all_files(self) -> Dict[str, Any]:
        """Process all CSV files in the directory."""
        files_to_process = self.get_file_processing_order()
        
        logger.info(f"Found {len(files_to_process)} CSV files to process")
        
        all_stats = []
        successful_files = 0
        failed_files = 0
        
        for filename in files_to_process:
            try:
                stats = self.process_file(filename)
                all_stats.append(stats)
                
                if stats['status'] == 'SUCCESS':
                    successful_files += 1
                    logger.info(f"✓ Successfully processed: {filename}")
                else:
                    failed_files += 1
                    logger.error(f"✗ Failed to process: {filename}")
                    
            except Exception as e:
                failed_files += 1
                logger.error(f"✗ Exception processing {filename}: {e}")
                all_stats.append({
                    'filename': filename,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Generate summary report
        summary = {
            'processing_date': datetime.now().isoformat(),
            'total_files_processed': len(files_to_process),
            'successful_files': successful_files,
            'failed_files': failed_files,
            'file_details': all_stats
        }
        
        return summary
    
    def generate_cleaning_report(self, summary: Dict[str, Any]) -> str:
        """Generate a comprehensive cleaning report."""
        report_lines = [
            "# CSV Cleaning Report",
            f"**Date:** {summary['processing_date']}",
            f"**Directory:** {self.input_dir}",
            "",
            "## Summary",
            f"- Total files processed: {summary['total_files_processed']}",
            f"- Successfully cleaned: {summary['successful_files']}",
            f"- Failed to process: {summary['failed_files']}",
            "",
            "## File Processing Details",
            ""
        ]
        
        for file_stats in summary['file_details']:
            if file_stats['status'] == 'SUCCESS':
                report_lines.extend([
                    f"### {file_stats['filename']} ✓",
                    f"- **Status:** Success",
                    f"- **Output:** {file_stats['output_file']}",
                    f"- **Rows processed:** {file_stats['total_rows']}",
                    f"- **Columns:** {file_stats['total_columns']}",
                    f"- **Encoding:** {file_stats['encoding_used']}",
                    ""
                ])
                
                if file_stats.get('issues_found'):
                    report_lines.append("**Issues Found:**")
                    for issue in file_stats['issues_found']:
                        report_lines.append(f"- {issue}")
                    report_lines.append("")
                
                if file_stats.get('issues_fixed'):
                    report_lines.append("**Issues Fixed:**")
                    for fix in file_stats['issues_fixed']:
                        report_lines.append(f"- {fix}")
                    report_lines.append("")
                
                if file_stats.get('empty_columns'):
                    report_lines.append("**Empty Columns:**")
                    for col in file_stats['empty_columns']:
                        report_lines.append(f"- {col}")
                    report_lines.append("")
                
            else:
                report_lines.extend([
                    f"### {file_stats['filename']} ✗",
                    f"- **Status:** Failed",
                    f"- **Error:** {file_stats.get('error', 'Unknown error')}",
                    ""
                ])
        
        return "\n".join(report_lines)

def main():
    """Main execution function."""
    # Set up paths
    input_directory = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao"
    
    # Initialize cleaner
    cleaner = CSVCleaner(input_directory)
    
    # Process all files
    logger.info("Starting CSV cleaning process...")
    summary = cleaner.process_all_files()
    
    # Generate and save report
    report = cleaner.generate_cleaning_report(summary)
    report_path = os.path.join(input_directory, "CSV_CLEANING_REPORT.md")
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    # Save detailed statistics as JSON
    stats_path = os.path.join(input_directory, "csv_cleaning_stats.json")
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Cleaning complete! Report saved to: {report_path}")
    logger.info(f"Detailed statistics saved to: {stats_path}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("CSV CLEANING SUMMARY")
    print(f"{'='*60}")
    print(f"Total files: {summary['total_files_processed']}")
    print(f"Successful: {summary['successful_files']}")
    print(f"Failed: {summary['failed_files']}")
    print(f"Success rate: {(summary['successful_files']/summary['total_files_processed']*100):.1f}%")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()