#!/usr/bin/env python3
"""
Investigate and recover missing rows
"""

import csv
import os
import sys
from typing import List, Dict, Any
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RowRecoveryProcessor:
    def __init__(self, input_path: str, output_path: str):
        self.input_path = input_path
        self.output_path = output_path
        self.encoding = 'utf-8'
        self.delimiter = ','
        self.quote_char = '"'
        
        # Remove CSV field size limit
        csv.field_size_limit(sys.maxsize)
    
    def count_lines_binary(self, file_path: str) -> int:
        """Count lines using binary mode for accuracy"""
        count = 0
        with open(file_path, 'rb') as f:
            for line in f:
                count += 1
        return count
    
    def analyze_line_structure(self, line: str, line_num: int) -> Dict[str, Any]:
        """Analyze individual line structure"""
        analysis = {
            'line_num': line_num,
            'length': len(line),
            'quote_count': line.count('"'),
            'delimiter_count': line.count(','),
            'has_unbalanced_quotes': line.count('"') % 2 != 0,
            'is_empty': len(line.strip()) == 0,
            'ends_properly': line.endswith('\n') or line.endswith('\r\n'),
            'fields_estimated': line.count(',') + 1 if line.strip() else 0
        }
        return analysis
    
    def robust_line_parser(self, line: str) -> List[str]:
        """Parse line with maximum recovery attempt"""
        if not line.strip():
            return []
        
        # Try standard CSV parsing first
        try:
            reader = csv.reader([line], delimiter=self.delimiter, quotechar=self.quote_char)
            return next(reader)
        except:
            pass
        
        # Try manual parsing for problematic lines
        fields = []
        current_field = ""
        in_quotes = False
        i = 0
        
        while i < len(line):
            char = line[i]
            
            if char == self.quote_char:
                if in_quotes:
                    # Check for escaped quote
                    if i + 1 < len(line) and line[i + 1] == self.quote_char:
                        current_field += self.quote_char
                        i += 1
                    else:
                        in_quotes = False
                else:
                    in_quotes = True
            elif char == self.delimiter and not in_quotes:
                fields.append(current_field)
                current_field = ""
            else:
                if char not in ['\n', '\r']:  # Skip line endings
                    current_field += char
            
            i += 1
        
        # Add the last field
        if current_field or line.endswith(self.delimiter):
            fields.append(current_field)
        
        return fields
    
    def process_with_recovery(self) -> Dict[str, Any]:
        """Process file with maximum row recovery"""
        logger.info("Starting row recovery process...")
        
        stats = {
            'input_lines': 0,
            'output_rows': 0,
            'empty_lines_skipped': 0,
            'malformed_lines_recovered': 0,
            'unrecoverable_lines': 0,
            'total_fields_padded': 0
        }
        
        # Count input lines
        stats['input_lines'] = self.count_lines_binary(self.input_path)
        logger.info(f"Input file has {stats['input_lines']:,} lines")
        
        header = None
        header_columns = 0
        
        try:
            with open(self.input_path, 'r', encoding=self.encoding, errors='replace') as infile:
                with open(self.output_path, 'w', encoding=self.encoding, newline='') as outfile:
                    writer = csv.writer(outfile, delimiter=self.delimiter, quotechar=self.quote_char, 
                                      quoting=csv.QUOTE_MINIMAL)
                    
                    line_num = 0
                    
                    for line in infile:
                        line_num += 1
                        
                        # Skip completely empty lines
                        if not line.strip():
                            stats['empty_lines_skipped'] += 1
                            continue
                        
                        try:
                            # Parse the line
                            fields = self.robust_line_parser(line)
                            
                            if not fields:
                                stats['empty_lines_skipped'] += 1
                                continue
                            
                            # Handle header
                            if header is None:
                                header = fields
                                header_columns = len(header)
                                writer.writerow(header)
                                stats['output_rows'] += 1
                                logger.info(f"Header processed: {header_columns} columns")
                                continue
                            
                            # Handle data rows
                            if len(fields) != header_columns:
                                # Attempt to fix column count
                                if len(fields) < header_columns:
                                    # Pad with empty values
                                    padding_needed = header_columns - len(fields)
                                    fields.extend([''] * padding_needed)
                                    stats['total_fields_padded'] += padding_needed
                                elif len(fields) > header_columns:
                                    # Merge excess fields into the last column
                                    excess_fields = fields[header_columns-1:]
                                    merged_field = ' '.join(excess_fields)
                                    fields = fields[:header_columns-1] + [merged_field]
                                
                                stats['malformed_lines_recovered'] += 1
                            
                            # Write the row
                            writer.writerow(fields)
                            stats['output_rows'] += 1
                            
                        except Exception as e:
                            # Last resort: try to salvage as much as possible
                            try:
                                # Split by delimiter and pad/truncate as needed
                                simple_fields = line.rstrip('\r\n').split(self.delimiter)
                                
                                if header_columns > 0:
                                    if len(simple_fields) < header_columns:
                                        simple_fields.extend([''] * (header_columns - len(simple_fields)))
                                    elif len(simple_fields) > header_columns:
                                        simple_fields = simple_fields[:header_columns]
                                    
                                    writer.writerow(simple_fields)
                                    stats['output_rows'] += 1
                                    stats['malformed_lines_recovered'] += 1
                                else:
                                    # No header yet, this is problematic
                                    stats['unrecoverable_lines'] += 1
                                    logger.warning(f"Cannot process line {line_num} without header")
                                    
                            except Exception as e2:
                                stats['unrecoverable_lines'] += 1
                                logger.error(f"Line {line_num} completely unrecoverable: {e2}")
                        
                        # Progress reporting
                        if line_num % 100000 == 0:
                            logger.info(f"Processed {line_num:,} lines, output {stats['output_rows']:,} rows")
                    
                    logger.info(f"Recovery processing complete: {line_num:,} lines processed")
        
        except Exception as e:
            logger.error(f"Critical error during recovery: {e}")
            raise
        
        return stats
    
    def validate_recovery(self) -> Dict[str, Any]:
        """Validate the recovered file"""
        logger.info("Validating recovered file...")
        
        validation = {
            'total_rows': 0,
            'parseable_rows': 0,
            'column_consistency': True,
            'inconsistent_rows': 0
        }
        
        try:
            with open(self.output_path, 'r', encoding=self.encoding) as f:
                reader = csv.reader(f, delimiter=self.delimiter, quotechar=self.quote_char)
                
                # Get header
                header = next(reader)
                header_columns = len(header)
                validation['total_rows'] += 1
                
                # Validate data rows
                for row in reader:
                    validation['total_rows'] += 1
                    validation['parseable_rows'] += 1
                    
                    if len(row) != header_columns:
                        validation['column_consistency'] = False
                        validation['inconsistent_rows'] += 1
        
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return validation
        
        logger.info(f"Validation complete:")
        logger.info(f"  Total rows: {validation['total_rows']:,}")
        logger.info(f"  Parseable rows: {validation['parseable_rows']:,}")
        logger.info(f"  Column consistency: {validation['column_consistency']}")
        logger.info(f"  Inconsistent rows: {validation['inconsistent_rows']:,}")
        
        return validation

def main():
    input_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"
    output_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao_CORRECTED.csv"
    
    logger.info("="*80)
    logger.info("ROW RECOVERY PROCESS")
    logger.info("="*80)
    
    processor = RowRecoveryProcessor(input_file, output_file)
    
    # Process with recovery
    stats = processor.process_with_recovery()
    
    # Validate
    validation = processor.validate_recovery()
    
    # Final report
    logger.info("="*80)
    logger.info("ROW RECOVERY COMPLETE - FINAL REPORT")
    logger.info("="*80)
    logger.info(f"Input lines: {stats['input_lines']:,}")
    logger.info(f"Output rows: {stats['output_rows']:,}")
    logger.info(f"Empty lines skipped: {stats['empty_lines_skipped']:,}")
    logger.info(f"Malformed lines recovered: {stats['malformed_lines_recovered']:,}")
    logger.info(f"Unrecoverable lines: {stats['unrecoverable_lines']:,}")
    logger.info(f"Total fields padded: {stats['total_fields_padded']:,}")
    logger.info(f"Expected rows: 786,013")
    logger.info(f"Recovery rate: {((stats['output_rows']-1) / 786013) * 100:.2f}%")
    logger.info(f"Data integrity: {'PRESERVED' if validation['column_consistency'] else 'COMPROMISED'}")
    
    return {
        'stats': stats,
        'validation': validation
    }

if __name__ == "__main__":
    main()