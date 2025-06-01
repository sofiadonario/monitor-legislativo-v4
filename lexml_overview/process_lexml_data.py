#!/usr/bin/env python3
"""
Script to process LexML consolidated data for application display
Processes lexml_consolidated_3.csv and prepares metadata for the application

Author: Assistant
Date: 2025-07-14
"""

import pandas as pd
import json
import re
from datetime import datetime
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LexMLDataProcessor:
    """
    Process LexML consolidated data for application display
    """
    
    def __init__(self, csv_file: str):
        self.csv_file = csv_file
        self.df = None
        self.processed_data = {}
        
    def load_data(self) -> bool:
        """
        Load the consolidated CSV data
        """
        try:
            logger.info(f"Loading data from {self.csv_file}")
            self.df = pd.read_csv(self.csv_file)
            logger.info(f"Loaded {len(self.df)} documents")
            return True
        except Exception as e:
            logger.error(f"Error loading data: {str(e)}")
            return False
    
    def clean_data(self):
        """
        Clean and prepare the data with more lenient approach
        """
        logger.info("Cleaning data with lenient approach...")
        
        # More lenient cleaning: keep documents with valid title OR valid URN
        # Remove only rows that have neither title nor URN
        initial_count = len(self.df)
        
        # Clean text fields first
        text_columns = ['title', 'document_description', 'document_summary']
        for col in text_columns:
            if col in self.df.columns:
                self.df[col] = self.df[col].astype(str).str.strip()
                self.df[col] = self.df[col].replace('nan', '')
        
        # Handle URN field - convert 'nan' strings to actual NaN
        if 'urn' in self.df.columns:
            self.df['urn'] = self.df['urn'].replace('nan', pd.NA)
        
        # Keep documents that have either a valid title OR a valid URN
        # A valid title is non-empty and not 'nan'
        # A valid URN is non-empty and not 'nan'
        valid_title = (self.df['title'].notna()) & (self.df['title'] != '') & (self.df['title'] != 'nan')
        valid_urn = (self.df['urn'].notna()) & (self.df['urn'] != '') & (self.df['urn'] != 'nan')
        
        # Keep rows that have either valid title OR valid URN
        self.df = self.df[valid_title | valid_urn]
        
        # Generate synthetic URNs for documents missing them
        self.df = self._generate_synthetic_urns()
        
        # Parse dates
        if 'enacting_date' in self.df.columns:
            self.df['enacting_date'] = pd.to_datetime(
                self.df['enacting_date'], 
                format='%d/%m/%Y', 
                errors='coerce'
            )
        
        final_count = len(self.df)
        dropped_count = initial_count - final_count
        
        logger.info(f"Initial documents: {initial_count}")
        logger.info(f"Documents dropped: {dropped_count}")
        logger.info(f"Cleaned data: {final_count} documents remaining")
        logger.info(f"Retention rate: {(final_count/initial_count)*100:.1f}%")
    
    def _generate_synthetic_urns(self):
        """
        Generate synthetic URNs for documents that are missing them
        """
        logger.info("Generating synthetic URNs for missing documents...")
        
        synthetic_count = 0
        
        for idx, row in self.df.iterrows():
            # Check if URN is missing or invalid
            urn = row.get('urn', '')
            if pd.isna(urn) or urn == '' or urn == 'nan':
                # Generate synthetic URN from URL
                url = row.get('url', '')
                if url and url != '' and url != 'nan':
                    # Extract URN from URL if possible
                    if 'urn:lex:' in url:
                        # Extract the URN part from the URL
                        urn_start = url.find('urn:lex:')
                        if urn_start != -1:
                            urn_end = url.find('"', urn_start)
                            if urn_end == -1:
                                urn_end = len(url)
                            synthetic_urn = url[urn_start:urn_end]
                            self.df.at[idx, 'urn'] = synthetic_urn
                            synthetic_count += 1
                    else:
                        # Create a synthetic URN based on URL and title
                        title = row.get('title', '')
                        if title and title != '' and title != 'nan':
                            # Create a hash-based URN
                            import hashlib
                            content = f"{url}{title}".encode('utf-8')
                            hash_value = hashlib.md5(content).hexdigest()[:8]
                            synthetic_urn = f"urn:lex:br:synthetic:doc:{hash_value}"
                            self.df.at[idx, 'urn'] = synthetic_urn
                            synthetic_count += 1
        
        logger.info(f"Generated {synthetic_count} synthetic URNs")
        return self.df
    
    def extract_metadata(self) -> Dict[str, Any]:
        """
        Extract comprehensive metadata from the data
        """
        logger.info("Extracting metadata...")
        
        metadata = {
            'total_documents': len(self.df),
            'search_terms': self.df['search_term'].nunique(),
            'date_range': {
                'start': self.df['enacting_date'].min().strftime('%Y-%m-%d') if not self.df['enacting_date'].isna().all() else None,
                'end': self.df['enacting_date'].max().strftime('%Y-%m-%d') if not self.df['enacting_date'].isna().all() else None
            },
            'document_types': self.df['urn_type'].value_counts().to_dict(),
            'top_search_terms': self.df['search_term'].value_counts().head(10).to_dict(),
            'regulatory_agencies': self._extract_agencies(),
            'jurisdictions': self._extract_jurisdictions(),
            'subject_categories': self._extract_subject_categories()
        }
        
        return metadata
    
    def _extract_agencies(self) -> List[str]:
        """
        Extract regulatory agencies mentioned in the data
        """
        agencies = []
        agency_keywords = ['ANP', 'ANTT', 'ANEEL', 'ANA', 'CONTRAN', 'DENATRAN', 'DNIT', 'IBAMA', 'INMETRO']
        
        for keyword in agency_keywords:
            if self.df['title'].str.contains(keyword, case=False, na=False).any():
                agencies.append(keyword)
        
        return agencies
    
    def _extract_jurisdictions(self) -> Dict[str, int]:
        """
        Extract jurisdiction information
        """
        jurisdictions = {}
        
        # Federal level
        federal_count = len(self.df[self.df['justice'].str.contains('Federal', case=False, na=False)])
        if federal_count > 0:
            jurisdictions['Federal'] = federal_count
        
        # State level
        state_count = len(self.df[self.df['justice'].str.contains('Estadual', case=False, na=False)])
        if state_count > 0:
            jurisdictions['Estadual'] = state_count
        
        return jurisdictions
    
    def _extract_subject_categories(self) -> Dict[str, int]:
        """
        Extract subject categories from document descriptions
        """
        categories = {
            'Transporte': 0,
            'Energia': 0,
            'Combustível': 0,
            'Veículo': 0,
            'Fiscalização': 0,
            'Tributação': 0,
            'Ambiente': 0
        }
        
        keywords = {
            'Transporte': ['transporte', 'frete', 'logística', 'carga'],
            'Energia': ['energia', 'elétrica', 'eletricidade'],
            'Combustível': ['combustível', 'diesel', 'gasolina', 'etanol', 'biodiesel'],
            'Veículo': ['veículo', 'caminhão', 'ônibus', 'automóvel'],
            'Fiscalização': ['fiscalização', 'inspeção', 'controle'],
            'Tributação': ['tributo', 'imposto', 'taxa', 'ICMS', 'PIS', 'COFINS'],
            'Ambiente': ['ambiente', 'poluição', 'emissão', 'sustentabilidade']
        }
        
        for category, terms in keywords.items():
            count = 0
            for term in terms:
                count += self.df['document_description'].str.contains(term, case=False, na=False).sum()
                count += self.df['title'].str.contains(term, case=False, na=False).sum()
            categories[category] = count
        
        return categories
    
    def prepare_display_data(self) -> List[Dict[str, Any]]:
        """
        Prepare data for application display
        """
        logger.info("Preparing display data...")
        
        display_data = []
        
        for _, row in self.df.iterrows():
            doc = {
                'id': row.get('urn', ''),
                'title': row.get('title', ''),
                'search_term': row.get('search_term', ''),
                'document_type': row.get('urn_type', ''),
                'enacting_date': row.get('enacting_date', ''),
                'url': row.get('url', ''),
                'description': row.get('document_description', ''),
                'summary': row.get('document_summary', ''),
                'jurisdiction': row.get('justice', ''),
                'region': row.get('region', ''),
                'authority': row.get('authority', ''),
                'metadata': {
                    'country': row.get('country', ''),
                    'state': row.get('state', ''),
                    'municipality': row.get('municipality', ''),
                    'court_class': row.get('court_class', ''),
                    'document_type_full': row.get('document_type_full', '')
                }
            }
            display_data.append(doc)
        
        return display_data
    
    def generate_statistics(self) -> Dict[str, Any]:
        """
        Generate comprehensive statistics
        """
        logger.info("Generating statistics...")
        
        # Calculate file size
        import os
        file_size_mb = 0
        if os.path.exists(self.csv_file):
            file_size_mb = round(os.path.getsize(self.csv_file) / (1024 * 1024), 2)
        
        stats = {
            'collection_info': {
                'total_documents': len(self.df),
                'unique_search_terms': self.df['search_term'].nunique(),
                'date_collected': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'file_size_mb': file_size_mb
            },
            'document_distribution': {
                'by_type': self.df['urn_type'].value_counts().to_dict(),
                'by_search_term': self.df['search_term'].value_counts().head(20).to_dict(),
                'by_jurisdiction': self.df['justice'].value_counts().head(10).to_dict()
            },
            'temporal_analysis': {
                'date_range': {
                    'earliest': self.df['enacting_date'].min().strftime('%Y-%m-%d') if not self.df['enacting_date'].isna().all() else None,
                    'latest': self.df['enacting_date'].max().strftime('%Y-%m-%d') if not self.df['enacting_date'].isna().all() else None
                },
                'decade_distribution': self._get_decade_distribution()
            },
            'content_analysis': {
                'subject_categories': self._extract_subject_categories(),
                'regulatory_agencies': self._extract_agencies(),
                'avg_title_length': round(self.df['title'].str.len().mean(), 1),
                'avg_description_length': round(self.df['document_description'].str.len().mean(), 1)
            }
        }
        
        return stats
    
    def _get_decade_distribution(self) -> Dict[str, int]:
        """
        Get distribution of documents by decade
        """
        decade_counts = {}
        
        for year in self.df['enacting_date'].dt.year.dropna():
            decade = f"{year // 10 * 10}s"
            decade_counts[decade] = decade_counts.get(decade, 0) + 1
        
        return decade_counts
    
    def save_processed_data(self, output_dir: str = "processed_data"):
        """
        Save processed data for application use
        """
        import os
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Save display data
        display_data = self.prepare_display_data()
        with open(f"{output_dir}/lexml_display_data.json", 'w', encoding='utf-8') as f:
            json.dump(display_data, f, ensure_ascii=False, indent=2, default=str)
        
        # Save metadata
        metadata = self.extract_metadata()
        with open(f"{output_dir}/lexml_metadata.json", 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2, default=str)
        
        # Save statistics
        statistics = self.generate_statistics()
        with open(f"{output_dir}/lexml_statistics.json", 'w', encoding='utf-8') as f:
            json.dump(statistics, f, ensure_ascii=False, indent=2, default=str)
        
        logger.info(f"Processed data saved to {output_dir}/")
        
        return {
            'display_data_file': f"{output_dir}/lexml_display_data.json",
            'metadata_file': f"{output_dir}/lexml_metadata.json",
            'statistics_file': f"{output_dir}/lexml_statistics.json"
        }

def main():
    """
    Main processing function
    """
    print("="*60)
    print("LEXML DATA PROCESSOR")
    print("="*60)
    
    processor = LexMLDataProcessor("lexml_consolidated_3.csv")
    
    # Load and process data
    if not processor.load_data():
        print("Failed to load data")
        return
    
    processor.clean_data()
    
    # Generate and save processed data
    output_files = processor.save_processed_data()
    
    print("\n" + "="*60)
    print("PROCESSING COMPLETE")
    print("="*60)
    print(f"Files generated:")
    for file_type, file_path in output_files.items():
        print(f"  {file_type}: {file_path}")
    
    # Display summary statistics
    stats = processor.generate_statistics()
    print(f"\nSummary:")
    print(f"  Total documents: {stats['collection_info']['total_documents']}")
    print(f"  Search terms: {stats['collection_info']['unique_search_terms']}")
    print(f"  File size: {stats['collection_info']['file_size_mb']} MB")

if __name__ == "__main__":
    main() 