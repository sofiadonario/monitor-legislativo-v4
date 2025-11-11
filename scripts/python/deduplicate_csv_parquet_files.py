#!/usr/bin/env python3
"""
COMPREHENSIVE CSV AND PARQUET DEDUPLICATION SCRIPT
This script applies deduplication to all CSV and parquet files in ./data_current/processed
"""

import pandas as pd
import numpy as np
import os
import json
from pathlib import Path
import logging
from datetime import datetime
import hashlib
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('./data_current/processed/deduplicated/deduplication.log'),
        logging.StreamHandler()
    ]
)

class DataDeduplicator:
    def __init__(self, base_path: str = "./data_current/processed"):
        self.base_path = Path(base_path)
        self.output_path = self.base_path / "deduplicated"
        self.output_path.mkdir(exist_ok=True)
        
        self.deduplication_results = {
            "timestamp": datetime.now().isoformat(),
            "files_processed": [],
            "total_original_rows": 0,
            "total_deduplicated_rows": 0,
            "duplication_patterns": {},
            "errors": []
        }
        
        logging.info(f"🚀 Starting deduplication process at {self.base_path}")
        
    def create_document_fingerprint(self, row: pd.Series) -> str:
        """Create a unique fingerprint for a document based on key identifying fields"""
        # Primary identifiers (in order of reliability)
        identifiers = []
        
        # URN is the most reliable identifier
        if pd.notna(row.get('urn', '')) and str(row.get('urn', '')).strip():
            identifiers.append(f"urn:{str(row['urn']).strip()}")
        
        # URL as secondary identifier
        if pd.notna(row.get('url', '')) and str(row.get('url', '')).strip():
            identifiers.append(f"url:{str(row['url']).strip()}")
            
        # Title + date + jurisdiction as tertiary identifier
        title = str(row.get('titulo', '')).strip() if pd.notna(row.get('titulo', '')) else ''
        date = str(row.get('data', '')).strip() if pd.notna(row.get('data', '')) else ''
        jurisdiction = str(row.get('jurisdicao', '')).strip() if pd.notna(row.get('jurisdicao', '')) else ''
        
        if title:
            identifiers.append(f"title_date_juris:{title}|{date}|{jurisdiction}")
        
        # Create fingerprint from available identifiers
        if identifiers:
            fingerprint_string = "::".join(identifiers)
        else:
            # Fallback: use all available fields
            available_fields = []
            for field in ['titulo', 'tipo', 'data', 'jurisdicao', 'ementa']:
                if pd.notna(row.get(field, '')) and str(row.get(field, '')).strip():
                    available_fields.append(f"{field}:{str(row[field]).strip()}")
            fingerprint_string = "::".join(available_fields)
        
        # Return hash of the fingerprint
        return hashlib.md5(fingerprint_string.encode('utf-8')).hexdigest()
    
    def deduplicate_dataframe(self, df: pd.DataFrame, source_file: str) -> Tuple[pd.DataFrame, Dict]:
        """Deduplicate a dataframe while preserving metadata"""
        logging.info(f"📊 Deduplicating {source_file}: {len(df):,} rows")
        
        if df.empty:
            return df, {"original_rows": 0, "deduplicated_rows": 0, "duplicates_removed": 0}
        
        original_count = len(df)
        
        # Create fingerprints
        df['_fingerprint'] = df.apply(self.create_document_fingerprint, axis=1)
        
        # Identify duplicates
        duplicate_groups = df.groupby('_fingerprint')
        
        deduplicated_rows = []
        duplication_stats = {
            "single_documents": 0,
            "duplicate_groups": 0,
            "max_duplicates_in_group": 0,
            "categories_merged": 0,
            "transport_categories_merged": 0
        }
        
        for fingerprint, group in duplicate_groups:
            if len(group) == 1:
                # No duplicates, keep as is
                row = group.iloc[0].copy()
                row['_deduplication_source'] = 'single'
                deduplicated_rows.append(row)
                duplication_stats["single_documents"] += 1
            else:
                # Multiple duplicates, merge them
                duplication_stats["duplicate_groups"] += 1
                duplication_stats["max_duplicates_in_group"] = max(
                    duplication_stats["max_duplicates_in_group"], len(group)
                )
                
                # Select the best representative (most complete record)
                def completeness_score(row):
                    score = 0
                    for field in ['ementa', 'assuntos', 'url', 'autor', 'numero']:
                        if pd.notna(row.get(field, '')) and str(row.get(field, '')).strip():
                            score += len(str(row[field]).strip())
                    return score
                
                group_with_scores = group.copy()
                group_with_scores['_completeness_score'] = group.apply(completeness_score, axis=1)
                best_row = group_with_scores.loc[group_with_scores['_completeness_score'].idxmax()].copy()
                
                # Merge categories and transport categories
                categories = group['categoria'].dropna().unique() if 'categoria' in group.columns else []
                transport_categories = group['modal'].dropna().unique() if 'modal' in group.columns else []
                
                if len(categories) > 1:
                    best_row['categoria'] = ', '.join(sorted(categories))
                    duplication_stats["categories_merged"] += 1
                
                if len(transport_categories) > 1:
                    best_row['modal'] = ', '.join(sorted(transport_categories))
                    duplication_stats["transport_categories_merged"] += 1
                
                # Add deduplication metadata
                best_row['_deduplication_source'] = 'merged'
                best_row['_original_count'] = len(group)
                best_row['_merged_categories'] = len(categories) if len(categories) > 1 else np.nan
                best_row['_merged_transport'] = len(transport_categories) if len(transport_categories) > 1 else np.nan
                
                deduplicated_rows.append(best_row)
        
        # Create deduplicated dataframe
        deduplicated_df = pd.DataFrame(deduplicated_rows)
        
        # Remove temporary columns
        columns_to_remove = ['_fingerprint', '_completeness_score']
        for col in columns_to_remove:
            if col in deduplicated_df.columns:
                deduplicated_df = deduplicated_df.drop(columns=[col])
        
        deduplicated_count = len(deduplicated_df)
        duplicates_removed = original_count - deduplicated_count
        
        result_stats = {
            "original_rows": original_count,
            "deduplicated_rows": deduplicated_count,
            "duplicates_removed": duplicates_removed,
            "reduction_percentage": round((duplicates_removed / original_count) * 100, 2) if original_count > 0 else 0,
            "duplication_stats": duplication_stats
        }
        
        logging.info(f"✅ {source_file}: {original_count:,} → {deduplicated_count:,} rows ({result_stats['reduction_percentage']}% reduction)")
        
        return deduplicated_df, result_stats
    
    def process_csv_file(self, file_path: Path) -> Dict:
        """Process a single CSV file"""
        try:
            logging.info(f"📄 Processing CSV: {file_path.name}")
            
            # Read CSV with error handling
            try:
                df = pd.read_csv(file_path, encoding='utf-8')
            except UnicodeDecodeError:
                df = pd.read_csv(file_path, encoding='latin-1')
            except Exception as e:
                logging.error(f"❌ Error reading {file_path}: {e}")
                return {"error": str(e)}
            
            # Deduplicate
            deduplicated_df, stats = self.deduplicate_dataframe(df, file_path.name)
            
            # Save deduplicated file
            output_file = self.output_path / f"{file_path.stem}_deduplicated.csv"
            deduplicated_df.to_csv(output_file, index=False, encoding='utf-8')
            
            # Also save as parquet for efficiency
            parquet_file = self.output_path / f"{file_path.stem}_deduplicated.parquet"
            deduplicated_df.to_parquet(parquet_file, index=False)
            
            stats["input_file"] = str(file_path)
            stats["output_csv"] = str(output_file)
            stats["output_parquet"] = str(parquet_file)
            
            return stats
            
        except Exception as e:
            error_msg = f"Error processing {file_path}: {str(e)}"
            logging.error(f"❌ {error_msg}")
            return {"error": error_msg}
    
    def process_parquet_file(self, file_path: Path) -> Dict:
        """Process a single Parquet file"""
        try:
            logging.info(f"📦 Processing Parquet: {file_path.name}")
            
            # Read Parquet
            df = pd.read_parquet(file_path)
            
            # Deduplicate
            deduplicated_df, stats = self.deduplicate_dataframe(df, file_path.name)
            
            # Save deduplicated file
            output_file = self.output_path / f"{file_path.stem}_deduplicated.parquet"
            deduplicated_df.to_parquet(output_file, index=False)
            
            # Also save as CSV for compatibility
            csv_file = self.output_path / f"{file_path.stem}_deduplicated.csv"
            deduplicated_df.to_csv(csv_file, index=False, encoding='utf-8')
            
            stats["input_file"] = str(file_path)
            stats["output_parquet"] = str(output_file)
            stats["output_csv"] = str(csv_file)
            
            return stats
            
        except Exception as e:
            error_msg = f"Error processing {file_path}: {str(e)}"
            logging.error(f"❌ {error_msg}")
            return {"error": error_msg}
    
    def find_all_files(self) -> List[Path]:
        """Find all CSV and Parquet files to process"""
        files_to_process = []
        
        # Find CSV files
        for csv_file in self.base_path.rglob("*.csv"):
            # Skip already processed files
            if "deduplicated" not in str(csv_file) and "cleaned" in str(csv_file):
                files_to_process.append(csv_file)
        
        # Find main parquet files (skip partitioned ones for now)
        parquet_files = list(self.base_path.rglob("*.parquet"))
        for parquet_file in parquet_files:
            if "deduplicated" not in str(parquet_file) and "part-" not in str(parquet_file):
                # Only process main parquet files, not partitioned ones
                if "single_file" in str(parquet_file) or parquet_file.name.startswith("brazilian_"):
                    files_to_process.append(parquet_file)
        
        logging.info(f"📋 Found {len(files_to_process)} files to process")
        return files_to_process
    
    def create_unified_deduplicated_dataset(self):
        """Create a single unified deduplicated dataset from all LexML files"""
        logging.info("🔄 Creating unified deduplicated dataset...")
        
        # Find all cleaned LexML CSV files
        lexml_files = []
        cleaned_dir = self.base_path / "cleaned"
        if cleaned_dir.exists():
            for csv_file in cleaned_dir.glob("lexml_*_cleaned.csv"):
                lexml_files.append(csv_file)
        
        if not lexml_files:
            logging.warning("⚠️ No LexML cleaned files found for unified dataset")
            return
        
        logging.info(f"📁 Found {len(lexml_files)} LexML files to unify")
        
        unified_data = []
        unified_stats = {
            "files_processed": 0,
            "total_original_rows": 0,
            "categories_found": set(),
            "transport_modes_found": set()
        }
        
        for file_path in lexml_files:
            try:
                logging.info(f"📄 Processing {file_path.name} for unified dataset")
                
                # Extract category and transport mode from filename
                filename = file_path.stem
                if "legislação" in filename or "legisla" in filename:
                    category = "Legislação"
                elif "jurisprudência" in filename or "jurisprud" in filename:
                    category = "Jurisprudência"
                elif "doutrina" in filename:
                    category = "Doutrina"
                elif "outros" in filename:
                    category = "Outros"
                elif "proposições" in filename or "proposi" in filename:
                    category = "Proposições"
                else:
                    category = "Unknown"
                
                # Extract transport mode
                if "aéreo" in filename or "aereo" in filename:
                    transport_mode = "Aéreo"
                elif "marítimo" in filename or "maritimo" in filename:
                    transport_mode = "Marítimo"
                elif "rodoviário" in filename or "rodoviario" in filename:
                    transport_mode = "Rodoviário"
                elif "geral" in filename:
                    transport_mode = "Geral"
                else:
                    transport_mode = "Unknown"
                
                # Read file
                try:
                    df = pd.read_csv(file_path, encoding='utf-8')
                except UnicodeDecodeError:
                    df = pd.read_csv(file_path, encoding='latin-1')
                
                # Add source metadata
                df['_source_file'] = file_path.name
                df['_extracted_category'] = category
                df['_extracted_transport_mode'] = transport_mode
                
                unified_data.append(df)
                unified_stats["files_processed"] += 1
                unified_stats["total_original_rows"] += len(df)
                unified_stats["categories_found"].add(category)
                unified_stats["transport_modes_found"].add(transport_mode)
                
            except Exception as e:
                logging.error(f"❌ Error processing {file_path}: {e}")
                continue
        
        if not unified_data:
            logging.error("❌ No data could be loaded for unified dataset")
            return
        
        # Combine all data
        logging.info("🔄 Combining all data...")
        combined_df = pd.concat(unified_data, ignore_index=True)
        
        logging.info(f"📊 Combined dataset: {len(combined_df):,} total rows")
        
        # Deduplicate the combined dataset
        logging.info("🔄 Deduplicating unified dataset...")
        deduplicated_df, dedup_stats = self.deduplicate_dataframe(combined_df, "unified_dataset")
        
        # Save unified deduplicated dataset
        unified_csv = self.output_path / "lexml_unified_deduplicated.csv"
        unified_parquet = self.output_path / "lexml_unified_deduplicated.parquet"
        
        deduplicated_df.to_csv(unified_csv, index=False, encoding='utf-8')
        deduplicated_df.to_parquet(unified_parquet, index=False)
        
        # Update results
        unified_stats["categories_found"] = list(unified_stats["categories_found"])
        unified_stats["transport_modes_found"] = list(unified_stats["transport_modes_found"])
        unified_stats.update(dedup_stats)
        unified_stats["output_csv"] = str(unified_csv)
        unified_stats["output_parquet"] = str(unified_parquet)
        
        self.deduplication_results["unified_dataset"] = unified_stats
        
        logging.info(f"✅ Unified deduplicated dataset created: {len(deduplicated_df):,} rows")
    
    def run_deduplication(self):
        """Run the complete deduplication process"""
        logging.info("🚀 Starting comprehensive deduplication process...")
        
        # Create unified dataset first
        self.create_unified_deduplicated_dataset()
        
        # Find and process individual files
        files_to_process = self.find_all_files()
        
        for file_path in files_to_process:
            if file_path.suffix.lower() == '.csv':
                result = self.process_csv_file(file_path)
            elif file_path.suffix.lower() == '.parquet':
                result = self.process_parquet_file(file_path)
            else:
                continue
            
            if "error" in result:
                self.deduplication_results["errors"].append(result)
            else:
                self.deduplication_results["files_processed"].append(result)
                self.deduplication_results["total_original_rows"] += result.get("original_rows", 0)
                self.deduplication_results["total_deduplicated_rows"] += result.get("deduplicated_rows", 0)
        
        # Calculate overall statistics
        total_original = self.deduplication_results["total_original_rows"]
        total_deduplicated = self.deduplication_results["total_deduplicated_rows"]
        
        if total_original > 0:
            overall_reduction = round((total_original - total_deduplicated) / total_original * 100, 2)
            self.deduplication_results["overall_reduction_percentage"] = overall_reduction
            self.deduplication_results["total_duplicates_removed"] = total_original - total_deduplicated
        
        # Save results
        results_file = self.output_path / "comprehensive_deduplication_results.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.deduplication_results, f, indent=2, ensure_ascii=False, default=str)
        
        # Create summary report
        self.create_summary_report()
        
        logging.info("✅ DEDUPLICATION PROCESS COMPLETED!")
    
    def create_summary_report(self):
        """Create a human-readable summary report"""
        report_lines = [
            "# COMPREHENSIVE DEDUPLICATION SUMMARY REPORT",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## OVERALL STATISTICS",
            f"- Files processed: {len(self.deduplication_results['files_processed'])}",
            f"- Total original rows: {self.deduplication_results['total_original_rows']:,}",
            f"- Total deduplicated rows: {self.deduplication_results['total_deduplicated_rows']:,}",
            f"- Total duplicates removed: {self.deduplication_results.get('total_duplicates_removed', 0):,}",
            f"- Overall reduction: {self.deduplication_results.get('overall_reduction_percentage', 0):.2f}%",
            "",
            "## UNIFIED DATASET",
        ]
        
        if "unified_dataset" in self.deduplication_results:
            unified = self.deduplication_results["unified_dataset"]
            report_lines.extend([
                f"- Original files combined: {unified.get('files_processed', 0)}",
                f"- Categories found: {', '.join(unified.get('categories_found', []))}",
                f"- Transport modes found: {', '.join(unified.get('transport_modes_found', []))}",
                f"- Total original rows: {unified.get('total_original_rows', 0):,}",
                f"- Final deduplicated rows: {unified.get('deduplicated_rows', 0):,}",
                f"- Reduction: {unified.get('reduction_percentage', 0):.2f}%",
            ])
        
        report_lines.extend([
            "",
            "## FILES PROCESSED",
        ])
        
        for file_result in self.deduplication_results["files_processed"]:
            if "error" not in file_result:
                filename = Path(file_result["input_file"]).name
                report_lines.append(
                    f"- {filename}: {file_result['original_rows']:,} → {file_result['deduplicated_rows']:,} "
                    f"({file_result['reduction_percentage']:.1f}% reduction)"
                )
        
        if self.deduplication_results["errors"]:
            report_lines.extend([
                "",
                "## ERRORS ENCOUNTERED",
            ])
            for error in self.deduplication_results["errors"]:
                report_lines.append(f"- {error.get('error', 'Unknown error')}")
        
        report_lines.extend([
            "",
            "## OUTPUT FILES",
            f"- All deduplicated files saved to: {self.output_path}",
            "- Each file has both CSV and Parquet versions",
            "- Unified dataset: lexml_unified_deduplicated.csv/parquet",
            "",
            "## DEDUPLICATION METHODOLOGY",
            "1. Document fingerprinting based on URN, URL, title+date+jurisdiction",
            "2. Preservation of most complete record for each unique document",
            "3. Merging of categories and transport modes for multi-category documents",
            "4. Addition of deduplication metadata for transparency",
            "",
            "✅ DEDUPLICATION COMPLETED SUCCESSFULLY"
        ])
        
        report_content = "\n".join(report_lines)
        
        # Save report
        report_file = self.output_path / "deduplication_summary_report.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        # Also print to console
        print("\n" + "="*80)
        print(report_content)
        print("="*80 + "\n")

def main():
    """Main execution function"""
    print("🚀 STARTING COMPREHENSIVE CSV/PARQUET DEDUPLICATION")
    print("="*80)
    
    try:
        # Initialize deduplicator
        deduplicator = DataDeduplicator()
        
        # Run deduplication
        deduplicator.run_deduplication()
        
        print("✅ DEDUPLICATION COMPLETED SUCCESSFULLY!")
        print(f"📁 Results saved to: {deduplicator.output_path}")
        
    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
        logging.error(f"Critical error in main: {e}")
        raise

if __name__ == "__main__":
    main()