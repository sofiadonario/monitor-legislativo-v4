#!/usr/bin/env python3
"""
Check for Excel serial dates and other date format issues
"""

import csv
import re
from datetime import datetime, timedelta
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def excel_serial_to_date(serial_number: str) -> str:
    """Convert Excel serial date to YYYY-MM-DD format"""
    try:
        serial = float(serial_number)
        
        if serial < 1 or serial > 100000:
            return serial_number  # Not a valid Excel date range
            
        # Excel epoch handling with leap year bug correction
        if serial >= 60:  # After the fake leap day (Feb 29, 1900)
            serial -= 1
            
        excel_epoch = datetime(1900, 1, 1)
        date_value = excel_epoch + timedelta(days=serial - 1)
        return date_value.strftime('%Y-%m-%d')
        
    except (ValueError, OverflowError):
        return serial_number

def analyze_date_formats():
    """Comprehensive date format analysis"""
    input_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao_CORRECTED.csv"
    
    logger.info("="*80)
    logger.info("COMPREHENSIVE DATE FORMAT ANALYSIS")
    logger.info("="*80)
    
    date_patterns = {
        'yyyy-mm-dd': re.compile(r'^\d{4}-\d{2}-\d{2}$'),
        'dd/mm/yyyy': re.compile(r'^\d{1,2}/\d{1,2}/\d{4}$'),
        'mm/dd/yyyy': re.compile(r'^\d{1,2}/\d{1,2}/\d{4}$'),  # Same pattern as dd/mm/yyyy
        'yyyy/mm/dd': re.compile(r'^\d{4}/\d{1,2}/\d{1,2}$'),
        'dd-mm-yyyy': re.compile(r'^\d{1,2}-\d{1,2}-\d{4}$'),
        'excel_serial': re.compile(r'^\d{1,5}(\.\d+)?$'),
        'datetime_iso': re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
        'datetime_space': re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),
        'partial_date': re.compile(r'^\d{4}-\d{2}$'),  # Year-month only
        'year_only': re.compile(r'^\d{4}$'),
    }
    
    date_stats = {
        'total_analyzed': 0,
        'empty_dates': 0,
        'pattern_counts': Counter(),
        'excel_serials_found': [],
        'unusual_formats': [],
        'conversion_candidates': []
    }
    
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        
        # Find date columns
        date_columns = []
        for i, col in enumerate(header):
            if 'data' in col.lower() or 'date' in col.lower():
                date_columns.append((i, col))
        
        logger.info(f"Found {len(date_columns)} date columns:")
        for idx, col in date_columns:
            logger.info(f"  Column {idx}: {col}")
        
        # Analyze date formats
        row_count = 0
        for row in reader:
            row_count += 1
            
            for col_idx, col_name in date_columns:
                if col_idx < len(row):
                    date_value = row[col_idx].strip()
                    date_stats['total_analyzed'] += 1
                    
                    if not date_value:
                        date_stats['empty_dates'] += 1
                        continue
                    
                    # Check patterns
                    pattern_found = False
                    for pattern_name, pattern_regex in date_patterns.items():
                        if pattern_regex.match(date_value):
                            date_stats['pattern_counts'][pattern_name] += 1
                            pattern_found = True
                            
                            # Check for Excel serial dates
                            if pattern_name == 'excel_serial':
                                try:
                                    serial_val = float(date_value)
                                    if 1 <= serial_val <= 100000:
                                        date_stats['excel_serials_found'].append({
                                            'row': row_count,
                                            'column': col_name,
                                            'value': date_value,
                                            'converted': excel_serial_to_date(date_value)
                                        })
                                        date_stats['conversion_candidates'].append((row_count, col_idx, date_value))
                                except:
                                    pass
                            
                            break
                    
                    if not pattern_found:
                        date_stats['unusual_formats'].append({
                            'row': row_count,
                            'column': col_name,
                            'value': date_value[:50]  # Truncate for display
                        })
            
            # Limit analysis for performance
            if row_count >= 50000:
                logger.info(f"Analyzed first {row_count:,} rows for performance")
                break
    
    # Report results
    logger.info(f"\nDate format analysis results:")
    logger.info(f"Total date values analyzed: {date_stats['total_analyzed']:,}")
    logger.info(f"Empty date values: {date_stats['empty_dates']:,}")
    logger.info(f"Excel serial dates found: {len(date_stats['excel_serials_found'])}")
    logger.info(f"Unusual formats found: {len(date_stats['unusual_formats'])}")
    
    logger.info(f"\nPattern distribution:")
    for pattern, count in date_stats['pattern_counts'].most_common():
        percentage = (count / date_stats['total_analyzed']) * 100
        logger.info(f"  {pattern}: {count:,} ({percentage:.1f}%)")
    
    if date_stats['excel_serials_found']:
        logger.info(f"\nExcel serial dates requiring conversion:")
        for i, excel_date in enumerate(date_stats['excel_serials_found'][:10]):
            logger.info(f"  Row {excel_date['row']}, {excel_date['column']}: {excel_date['value']} -> {excel_date['converted']}")
        if len(date_stats['excel_serials_found']) > 10:
            logger.info(f"  ... and {len(date_stats['excel_serials_found']) - 10} more")
    
    if date_stats['unusual_formats']:
        logger.info(f"\nUnusual date formats found:")
        for i, unusual in enumerate(date_stats['unusual_formats'][:10]):
            logger.info(f"  Row {unusual['row']}, {unusual['column']}: {unusual['value']}")
        if len(date_stats['unusual_formats']) > 10:
            logger.info(f"  ... and {len(date_stats['unusual_formats']) - 10} more")
    
    return date_stats

def apply_date_corrections():
    """Apply date format corrections if needed"""
    date_stats = analyze_date_formats()
    
    if not date_stats['excel_serials_found']:
        logger.info("No Excel serial dates found - no date corrections needed")
        return
    
    logger.info(f"Found {len(date_stats['excel_serials_found'])} Excel serial dates to convert")
    
    # If Excel serial dates were found, we would apply corrections here
    # For now, just report what would be corrected
    logger.info("Date conversion would be applied to:")
    for excel_date in date_stats['excel_serials_found'][:5]:
        logger.info(f"  {excel_date['value']} -> {excel_date['converted']}")

if __name__ == "__main__":
    apply_date_corrections()