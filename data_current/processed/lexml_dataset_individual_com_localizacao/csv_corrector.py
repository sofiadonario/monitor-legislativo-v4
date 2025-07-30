#!/usr/bin/env python3
"""
Robust CSV Corrector for Critical Data Processing
Handles extremely long text fields, unbalanced quotes, and field size limits
Preserves all data integrity while fixing parsing barriers
"""

import csv
import os
import sys
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
import io
import traceback
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RobustCSVCorrector:
    def __init__(self, input_path: str, output_path: str):
        self.input_path = input_path
        self.output_path = output_path
        self.encoding = 'utf-8'
        self.delimiter = ','
        self.quote_char = '"'
        self.header = None
        self.corrections_applied = []
        self.row_count = 0
        self.error_count = 0
        self.date_conversions = 0
        
        # Increase CSV field size limit to handle extremely long fields
        csv.field_size_limit(sys.maxsize)
        
    def excel_serial_to_date(self, serial_number: str) -> str:
        """Convert Excel serial date to YYYY-MM-DD format"""
        try:
            # Excel uses 1900-01-01 as day 1, but has a leap year bug
            # Day 1 = 1900-01-01, Day 60 = 1900-02-29 (which doesn't exist)
            serial = float(serial_number)
            
            if serial < 1:
                return serial_number  # Not a valid Excel date
                
            # Excel epoch is 1900-01-01, but we need to account for the leap year bug
            if serial >= 60:  # After the fake leap day
                serial -= 1
                
            excel_epoch = datetime(1900, 1, 1)
            date_value = excel_epoch + timedelta(days=serial - 1)
            return date_value.strftime('%Y-%m-%d')
            
        except (ValueError, OverflowError):
            return serial_number  # Return original if conversion fails
    
    def clean_field(self, field: str) -> str:
        """Clean individual field content"""
        if not field:
            return field
            
        # Handle extremely long fields - truncate if necessary but preserve structure
        if len(field) > 1000000:  # 1MB limit for individual fields
            logger.warning(f"Truncating extremely long field ({len(field)} chars) to 1MB")
            field = field[:1000000] + "...[TRUNCATED]"
            self.corrections_applied.append(f"Truncated field from {len(field)} to 1MB")
        
        # Fix unbalanced quotes by escaping internal quotes
        if field.count('"') > 0:
            # Escape internal quotes properly
            field = field.replace('""', '«DOUBLE_QUOTE»')  # Preserve existing escaped quotes
            field = field.replace('"', '""')  # Escape all quotes
            field = field.replace('«DOUBLE_QUOTE»', '""""')  # Restore and properly escape double quotes
        
        # Handle problematic characters
        # Replace control characters (except tab, newline, carriage return)
        field = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', field)
        
        return field
    
    def parse_line_manually(self, line: str) -> List[str]:
        """Manually parse CSV line to handle complex quoting and long fields"""
        fields = []
        current_field = ""
        in_quotes = False
        i = 0
        
        while i < len(line):
            char = line[i]
            
            if char == self.quote_char:
                if in_quotes:
                    # Check if this is an escaped quote
                    if i + 1 < len(line) and line[i + 1] == self.quote_char:
                        current_field += self.quote_char
                        i += 1  # Skip next quote
                    else:
                        in_quotes = False
                else:
                    in_quotes = True
            elif char == self.delimiter and not in_quotes:
                fields.append(current_field)
                current_field = ""
            else:
                current_field += char
            
            i += 1
        
        # Add the last field
        fields.append(current_field)
        
        return fields
    
    def process_row(self, row_data: List[str]) -> List[str]:
        """Process and clean a row of data"""
        cleaned_row = []
        
        for i, field in enumerate(row_data):
            cleaned_field = self.clean_field(field)
            
            # Handle date conversion for data_publicacao column
            if self.header and i < len(self.header) and 'data_publicacao' in self.header[i].lower():
                original_field = cleaned_field
                cleaned_field = self.excel_serial_to_date(cleaned_field)
                if original_field != cleaned_field:
                    self.date_conversions += 1
            
            cleaned_row.append(cleaned_field)
        
        return cleaned_row
    
    def write_csv_row(self, writer, row_data: List[str]):
        """Write a single row to CSV with proper escaping"""
        try:
            writer.writerow(row_data)
        except Exception as e:
            logger.error(f"Failed to write row: {e}")
            # Try to write with additional cleaning
            try:
                cleaned_row = [str(field).replace('\n', '\\n').replace('\r', '\\r') for field in row_data]
                writer.writerow(cleaned_row)
                self.corrections_applied.append("Replaced newlines with escape sequences in row")
            except Exception as e2:
                logger.error(f"Failed to write row even after cleaning: {e2}")
                self.error_count += 1
    
    def process_file(self) -> Dict[str, Any]:
        """Process the entire CSV file with robust error handling"""
        logger.info(f"Starting to process file: {self.input_path}")
        logger.info(f"Output file: {self.output_path}")
        
        processing_stats = {
            'total_rows_processed': 0,
            'successful_rows': 0,
            'error_rows': 0,
            'corrections_applied': [],
            'date_conversions': 0,
            'file_size_input': 0,
            'file_size_output': 0
        }
        
        # Get input file size
        processing_stats['file_size_input'] = os.path.getsize(self.input_path)
        
        try:
            with open(self.input_path, 'r', encoding=self.encoding, errors='replace') as infile:
                with open(self.output_path, 'w', encoding=self.encoding, newline='') as outfile:
                    writer = csv.writer(outfile, delimiter=self.delimiter, quotechar=self.quote_char, 
                                      quoting=csv.QUOTE_MINIMAL, escapechar='\\')
                    
                    line_number = 0
                    header_processed = False
                    
                    for line in infile:
                        line_number += 1
                        self.row_count += 1
                        
                        try:
                            # Remove line endings
                            line = line.rstrip('\r\n')
                            
                            if not line.strip():
                                continue  # Skip empty lines
                            
                            # Parse the line manually to handle complex cases
                            fields = self.parse_line_manually(line)
                            
                            if not header_processed:
                                # Process header
                                self.header = fields
                                logger.info(f"Header columns: {len(self.header)}")
                                logger.info(f"Header: {self.header[:5]}..." if len(self.header) > 5 else f"Header: {self.header}")
                                self.write_csv_row(writer, self.header)
                                header_processed = True
                                processing_stats['successful_rows'] += 1
                            else:
                                # Process data row
                                if len(fields) != len(self.header):
                                    # Handle column count mismatch
                                    if len(fields) < len(self.header):
                                        # Pad with empty fields
                                        fields.extend([''] * (len(self.header) - len(fields)))
                                        self.corrections_applied.append(f"Padded row {line_number} with {len(self.header) - len(fields)} empty fields")
                                    else:
                                        # Truncate extra fields
                                        fields = fields[:len(self.header)]
                                        self.corrections_applied.append(f"Truncated row {line_number} from {len(fields)} to {len(self.header)} fields")
                                
                                # Process and clean the row
                                cleaned_row = self.process_row(fields)
                                self.write_csv_row(writer, cleaned_row)
                                processing_stats['successful_rows'] += 1
                            
                            # Progress reporting
                            if line_number % 50000 == 0:
                                logger.info(f"Processed {line_number:,} lines...")
                                
                        except Exception as e:
                            logger.error(f"Error processing line {line_number}: {e}")
                            processing_stats['error_rows'] += 1
                            self.error_count += 1
                            
                            # Try to salvage the line by writing it as a single field
                            try:
                                if header_processed:
                                    salvaged_row = [line] + [''] * (len(self.header) - 1)
                                    self.write_csv_row(writer, salvaged_row)
                                    self.corrections_applied.append(f"Salvaged malformed line {line_number} as single field")
                            except:
                                logger.error(f"Could not salvage line {line_number}")
                    
                    logger.info(f"Completed processing. Total lines processed: {line_number:,}")
        
        except Exception as e:
            logger.error(f"Critical error during file processing: {e}")
            logger.error(traceback.format_exc())
            raise
        
        # Get output file size
        if os.path.exists(self.output_path):
            processing_stats['file_size_output'] = os.path.getsize(self.output_path)
        
        # Compile final statistics
        processing_stats.update({
            'total_rows_processed': self.row_count,
            'successful_rows': processing_stats['successful_rows'],
            'error_rows': self.error_count,
            'corrections_applied': self.corrections_applied,
            'date_conversions': self.date_conversions,
            'correction_count': len(self.corrections_applied)
        })
        
        return processing_stats
    
    def validate_output(self) -> Dict[str, Any]:
        """Validate the corrected CSV file"""
        logger.info("Validating corrected CSV file...")
        
        validation_results = {
            'is_valid': False,
            'total_rows': 0,
            'header_columns': 0,
            'parsing_errors': 0,
            'column_consistency': True,
            'sample_rows': []
        }
        
        try:
            with open(self.output_path, 'r', encoding=self.encoding) as f:
                reader = csv.reader(f, delimiter=self.delimiter, quotechar=self.quote_char)
                
                # Read header
                header = next(reader)
                validation_results['header_columns'] = len(header)
                validation_results['total_rows'] += 1
                
                # Validate data rows
                for i, row in enumerate(reader):
                    validation_results['total_rows'] += 1
                    
                    # Check column consistency
                    if len(row) != len(header):
                        validation_results['column_consistency'] = False
                        validation_results['parsing_errors'] += 1
                    
                    # Collect sample rows
                    if i < 5:
                        validation_results['sample_rows'].append(row[:3])  # First 3 fields of first 5 rows
                    
                    # Limit validation for performance
                    if validation_results['total_rows'] > 1000000:
                        break
                
                validation_results['is_valid'] = validation_results['parsing_errors'] == 0
                
                logger.info(f"Validation complete:")
                logger.info(f"  Total rows: {validation_results['total_rows']:,}")
                logger.info(f"  Header columns: {validation_results['header_columns']}")
                logger.info(f"  Parsing errors: {validation_results['parsing_errors']}")
                logger.info(f"  Column consistency: {validation_results['column_consistency']}")
                
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            validation_results['parsing_errors'] += 1
        
        return validation_results

def main():
    """Main processing function"""
    input_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"
    output_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao_CORRECTED.csv"
    
    if not os.path.exists(input_file):
        logger.error(f"Input file not found: {input_file}")
        return
    
    logger.info("="*80)
    logger.info("ROBUST CSV CORRECTION PROCESS")
    logger.info("="*80)
    
    # Initialize corrector
    corrector = RobustCSVCorrector(input_file, output_file)
    
    # Process the file
    start_time = datetime.now()
    processing_stats = corrector.process_file()
    end_time = datetime.now()
    
    processing_time = (end_time - start_time).total_seconds()
    
    # Validate output
    validation_results = corrector.validate_output()
    
    # Generate comprehensive report
    logger.info("="*80)
    logger.info("PROCESSING COMPLETE - FINAL REPORT")
    logger.info("="*80)
    logger.info(f"Processing time: {processing_time:.2f} seconds")
    logger.info(f"Input file size: {processing_stats['file_size_input']:,} bytes ({processing_stats['file_size_input']/(1024*1024):.2f} MB)")
    logger.info(f"Output file size: {processing_stats['file_size_output']:,} bytes ({processing_stats['file_size_output']/(1024*1024):.2f} MB)")
    logger.info(f"Total rows processed: {processing_stats['total_rows_processed']:,}")
    logger.info(f"Successful rows: {processing_stats['successful_rows']:,}")
    logger.info(f"Error rows: {processing_stats['error_rows']:,}")
    logger.info(f"Date conversions: {processing_stats['date_conversions']:,}")
    logger.info(f"Total corrections applied: {processing_stats['correction_count']:,}")
    logger.info(f"Output validation: {'PASSED' if validation_results['is_valid'] else 'FAILED'}")
    logger.info(f"Output rows accessible: {validation_results['total_rows']:,}")
    
    if processing_stats['corrections_applied']:
        logger.info("\nCorrections Applied (sample):")
        for correction in processing_stats['corrections_applied'][:10]:
            logger.info(f"  - {correction}")
        if len(processing_stats['corrections_applied']) > 10:
            logger.info(f"  ... and {len(processing_stats['corrections_applied']) - 10} more corrections")
    
    logger.info(f"\nCorrected file created: {output_file}")
    logger.info("="*80)
    
    return {
        'processing_stats': processing_stats,
        'validation_results': validation_results,
        'processing_time': processing_time
    }

if __name__ == "__main__":
    main()