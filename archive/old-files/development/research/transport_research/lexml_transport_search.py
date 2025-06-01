#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LexML Legislative Monitor - Transport Cargo Search Script
Optimized for WSL Ubuntu environment
Searches for transport-related legislation in Brazilian federal law database
"""

import requests
import xml.etree.ElementTree as ET
import csv
import time
import os
import sys
import signal
import json
from datetime import datetime
from urllib.parse import quote
import logging
from pathlib import Path
import threading
from tqdm import tqdm
import argparse

# Configure logging with WSL-friendly paths
log_dir = Path.home() / '.lexml_logs'
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / f'lexml_search_{datetime.now().strftime("%Y%m%d")}.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class LexMLSearcher:
    def __init__(self, output_dir=None, resume=False):
        self.base_url = "https://www.lexml.gov.br/busca/SRU"
        self.results = {
            'lei': [],
            'decreto': [],
            'portaria': [],
            'resolucao': [],
            'medida_provisoria': [],
            'projeto_lei': [],
            'instrucao_normativa': [],
            'outros': []
        }
        
        # WSL-optimized output directory
        if output_dir:
            self.output_dir = Path(output_dir).expanduser()
        else:
            # Use home directory in WSL for better performance
            self.output_dir = Path.home() / 'lexml_results'
        
        self.output_dir.mkdir(exist_ok=True)
        
        # Progress tracking
        self.progress_file = self.output_dir / '.progress.json'
        self.processed_terms = set()
        self.stop_signal = False
        
        # Resume capability
        if resume and self.progress_file.exists():
            self.load_progress()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        logger.info("\nReceived interrupt signal. Saving progress...")
        self.stop_signal = True
        self.save_progress()
        logger.info("Progress saved. You can resume later with --resume flag")
        sys.exit(0)
    
    def save_progress(self):
        """Save current progress for resume capability"""
        progress_data = {
            'processed_terms': list(self.processed_terms),
            'results': {k: len(v) for k, v in self.results.items()},
            'timestamp': datetime.now().isoformat()
        }
        
        with open(self.progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, ensure_ascii=False, indent=2)
    
    def load_progress(self):
        """Load previous progress"""
        try:
            with open(self.progress_file, 'r', encoding='utf-8') as f:
                progress_data = json.load(f)
                self.processed_terms = set(progress_data.get('processed_terms', []))
                logger.info(f"Resumed from previous session. {len(self.processed_terms)} terms already processed.")
        except Exception as e:
            logger.error(f"Error loading progress: {e}")
    
    def build_search_terms(self):
        """Build comprehensive list of search terms from the document"""
        
        # Basic transport terms
        general_terms = [
            '"transporte de carga"',
            '"transporte rodoviário de carga"',
            '"logística de carga"',
            'frete', 'fretamento',
            'caminhão', 'caminhões',
            '"veículos pesados"',
            '"veículos de carga"',
            '"veículos comerciais"',
            '"transporte de mercadorias"',
            '"modal rodoviário"'
        ]
        
        # Fuel and energy terms
        fuel_terms = [
            '"gás natural veicular" AND (caminhão OR carga)',
            'biometano AND (transporte OR "veículos pesados")',
            'diesel AND (caminhão OR transporte)',
            'biodiesel AND ("veículos pesados" OR carga)',
            '"diesel verde"',
            '"combustível sustentável" AND transporte',
            'hidrogênio AND (caminhão OR "transporte pesado")',
            'etanol AND "veículos pesados"',
            'SAF AND "carga aérea"'
        ]
        
        # Energy efficiency and emissions
        efficiency_terms = [
            '"eficiência energética" AND ("veículos pesados" OR caminhão)',
            'emissões AND ("transporte de carga" OR caminhão)',
            'descarbonização AND (transporte OR logística)',
            '"gases de efeito estufa" AND transporte',
            '"rotulagem veicular" AND carga',
            '"consumo de combustível" AND (caminhão OR pesados)'
        ]
        
        # Technology and innovation
        tech_terms = [
            '"tecnologias assistivas" AND (caminhão OR direção)',
            '"veículos autônomos" AND carga',
            'telemetria AND transporte',
            'rastreamento AND carga',
            'motorização AND "veículos pesados"',
            'conversão AND (diesel OR "gás natural")'
        ]
        
        # Infrastructure
        infra_terms = [
            '"postos de abastecimento" AND ("gás natural" OR biometano)',
            'infraestrutura AND ("combustíveis alternativos" OR carga)',
            '"terminais de carga"',
            '"centros de distribuição"',
            'armazéns AND logística'
        ]
        
        # Regulation and standards
        regulation_terms = [
            'CONTRAN AND (caminhão OR carga)',
            'ANTT AND (transporte OR frete)',
            'registro AND transportador',
            'habilitação AND ("transporte de carga" OR motorista)',
            'licenciamento AND "veículos pesados"',
            'RNTRC',
            '"segurança veicular" AND carga'
        ]
        
        # Incentives and taxation
        tax_terms = [
            'IPI AND (caminhão OR "veículos pesados")',
            'ICMS AND transporte',
            '"incentivo fiscal" AND (transporte OR logística)',
            'isenção AND ("veículos pesados" OR combustível)',
            '"benefício tributário" AND transporte',
            'financiamento AND (caminhão OR frota)'
        ]
        
        # Rota 2030 and Paten specific
        rota_terms = [
            '"Rota 2030" AND (logística OR transporte)',
            'Paten AND transporte',
            '"mobilidade e logística"',
            '"transição energética" AND transporte',
            '"desenvolvimento sustentável" AND logística',
            '"P&D" AND (automotivo OR transporte)'
        ]
        
        # Machinery and equipment
        machinery_terms = [
            '"máquinas agrícolas"',
            '"implementos rodoviários"',
            'reboque', '"semi-reboque"',
            'carreta',
            'bitrem', 'rodotrem',
            '"equipamentos de transporte"'
        ]
        
        # Operations and services
        operations_terms = [
            '"transportador autônomo"',
            '"empresa de transporte"',
            '"operador logístico"',
            'embarcador',
            'terceirização AND transporte',
            '"contrato de frete"',
            '"tabela de frete"'
        ]
        
        # Boolean combinations
        boolean_combinations = [
            '("transporte de carga" OR "veículos pesados") AND ("gás natural" OR biometano OR biodiesel)',
            '(caminhão OR "veículo pesado") AND (incentivo OR benefício OR isenção)',
            '("eficiência energética" OR emissões) AND ("transporte rodoviário" OR logística)',
            '(Rota 2030 OR Paten) AND (transporte OR logística OR carga)'
        ]
        
        # Combine all terms
        all_terms = (general_terms + fuel_terms + efficiency_terms + 
                    tech_terms + infra_terms + regulation_terms + 
                    tax_terms + rota_terms + machinery_terms + 
                    operations_terms + boolean_combinations)
        
        return all_terms
    
    def build_query_url(self, search_term, start_record=1, maximum_records=100):
        """Build the SRU query URL with filters"""
        
        # Add legislative document type filter to search term
        legislative_filter = '(lei OR decreto OR portaria OR resolução OR "medida provisória" OR "projeto de lei" OR "instrução normativa")'
        
        # Build the complete query with date range
        date_filter = ' OR '.join([f'date any "{year}"' for year in range(2015, 2026)])
        query = f'({search_term}) AND {legislative_filter} AND localidade any "Brasil" AND autoridade any "Federal" AND ({date_filter})'
        
        # URL encode the query
        encoded_query = quote(query)
        
        # Build complete URL
        url = f"{self.base_url}?operation=searchRetrieve&query={encoded_query}&startRecord={start_record}&maximumRecords={maximum_records}"
        
        return url
    
    def parse_sru_response(self, xml_content):
        """Parse SRU XML response and extract relevant data"""
        try:
            # Parse XML with UTF-8 encoding
            root = ET.fromstring(xml_content.decode('utf-8', errors='replace'))
            
            # Define namespaces
            namespaces = {
                'srw': 'http://www.loc.gov/zing/srw/',
                'dc': 'http://purl.org/dc/elements/1.1/',
                'srw_dc': 'info:srw/schema/1/dc-schema'
            }
            
            records = []
            
            # Find all records
            for record in root.findall('.//srw:record', namespaces):
                record_data = {}
                
                # Helper function to safely extract text
                def safe_extract(elem_name, namespace=None):
                    if namespace:
                        elem = record.find(f'.//{namespace}:{elem_name}', namespaces)
                    else:
                        elem = record.find(f'.//{elem_name}')
                    return elem.text if elem is not None and elem.text else ''
                
                # Extract all fields
                record_data['urn'] = safe_extract('urn')
                record_data['tipo_documento'] = safe_extract('tipoDocumento')
                record_data['data'] = safe_extract('date', 'dc')
                record_data['titulo'] = safe_extract('title', 'dc')
                record_data['descricao'] = safe_extract('description', 'dc')
                record_data['assunto'] = safe_extract('subject', 'dc')
                record_data['identificador'] = safe_extract('identifier', 'dc')
                record_data['localidade'] = safe_extract('localidade')
                record_data['autoridade'] = safe_extract('autoridade')
                
                # Only add if we have at least a title or URN
                if record_data['titulo'] or record_data['urn']:
                    records.append(record_data)
            
            # Extract total number of records
            num_records_elem = root.find('.//srw:numberOfRecords', namespaces)
            total_records = 0
            if num_records_elem is not None and num_records_elem.text:
                try:
                    total_records = int(num_records_elem.text)
                except ValueError:
                    total_records = 0
            
            return records, total_records
            
        except Exception as e:
            logger.error(f"Error parsing XML: {e}")
            return [], 0
    
    def categorize_document(self, tipo_documento, titulo):
        """Categorize document based on type"""
        tipo_lower = tipo_documento.lower() if tipo_documento else ''
        titulo_lower = titulo.lower() if titulo else ''
        
        if 'lei' in tipo_lower and 'projeto' not in tipo_lower:
            return 'lei'
        elif 'decreto' in tipo_lower:
            return 'decreto'
        elif 'portaria' in tipo_lower:
            return 'portaria'
        elif 'resolução' in tipo_lower or 'resolucao' in tipo_lower:
            return 'resolucao'
        elif 'medida provisória' in tipo_lower or 'medida provisoria' in tipo_lower:
            return 'medida_provisoria'
        elif 'projeto' in tipo_lower and 'lei' in tipo_lower:
            return 'projeto_lei'
        elif 'instrução normativa' in tipo_lower or 'instrucao normativa' in tipo_lower:
            return 'instrucao_normativa'
        else:
            return 'outros'
    
    def search_term(self, search_term, pbar=None):
        """Search for a specific term and retrieve all results"""
        
        start_record = 1
        maximum_records = 100
        total_retrieved = 0
        
        while True:
            if self.stop_signal:
                break
                
            try:
                # Build URL
                url = self.build_query_url(search_term, start_record, maximum_records)
                
                # Make request with timeout and retries
                for attempt in range(3):
                    try:
                        response = requests.get(url, timeout=30)
                        response.raise_for_status()
                        break
                    except requests.exceptions.RequestException as e:
                        if attempt == 2:
                            raise e
                        time.sleep(2 ** attempt)
                
                # Parse response
                records, total_records = self.parse_sru_response(response.content)
                
                # Add search term to each record
                for record in records:
                    record['termo_busca'] = search_term
                    category = self.categorize_document(
                        record.get('tipo_documento', ''),
                        record.get('titulo', '')
                    )
                    self.results[category].append(record)
                
                total_retrieved += len(records)
                
                # Update progress bar description
                if pbar:
                    pbar.set_postfix({'Retrieved': f'{total_retrieved}/{total_records}'})
                
                # Check if we've retrieved all records
                if total_retrieved >= total_records or len(records) == 0:
                    break
                
                # Update start record for next page
                start_record += maximum_records
                
                # Rate limiting
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error searching for '{search_term}': {e}")
                break
    
    def search_all_terms(self):
        """Search for all terms with progress tracking"""
        terms = self.build_search_terms()
        
        # Filter out already processed terms
        remaining_terms = [t for t in terms if t not in self.processed_terms]
        
        if not remaining_terms:
            logger.info("All terms have been processed already!")
            return
        
        logger.info(f"Processing {len(remaining_terms)} remaining terms...")
        
        # Create progress bar
        with tqdm(total=len(remaining_terms), desc="Searching terms", unit="term") as pbar:
            for term in remaining_terms:
                if self.stop_signal:
                    break
                
                pbar.set_description(f"Searching: {term[:50]}...")
                self.search_term(term, pbar)
                self.processed_terms.add(term)
                
                # Save progress periodically
                if len(self.processed_terms) % 5 == 0:
                    self.save_progress()
                
                pbar.update(1)
                
                # Rate limiting between searches
                time.sleep(2)
    
    def deduplicate_results(self):
        """Remove duplicate records based on URN"""
        logger.info("Removing duplicates...")
        
        for category in self.results:
            seen_urns = set()
            unique_records = []
            
            for record in self.results[category]:
                urn = record.get('urn', '')
                if urn and urn not in seen_urns:
                    seen_urns.add(urn)
                    unique_records.append(record)
                elif not urn:
                    # Keep records without URN (shouldn't happen but just in case)
                    unique_records.append(record)
            
            self.results[category] = unique_records
    
    def export_to_csv(self):
        """Export results to CSV files by document category"""
        
        # Deduplicate before exporting
        self.deduplicate_results()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export each category
        for category, records in self.results.items():
            if records:  # Only create file if there are records
                filename = self.output_dir / f'{category}_{timestamp}.csv'
                
                # Write CSV with proper encoding for WSL
                with open(filename, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    fieldnames = ['urn', 'tipo_documento', 'data', 'titulo', 'descricao', 
                                'assunto', 'identificador', 'localidade', 'autoridade', 'termo_busca']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    writer.writerows(records)
                
                # Set proper permissions for WSL
                os.chmod(filename, 0o644)
                logger.info(f"Exported {len(records)} records to {filename}")
        
        # Create summary file
        summary_file = self.output_dir / f'summary_{timestamp}.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("LexML Search Summary\n")
            f.write("=" * 50 + "\n")
            f.write(f"Search Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Date Range: 2015-2025\n")
            f.write(f"Location: Brasil (Federal)\n")
            f.write(f"Terms Processed: {len(self.processed_terms)}\n")
            f.write("\nResults by Category:\n")
            f.write("-" * 30 + "\n")
            
            total = 0
            for category, records in self.results.items():
                count = len(records)
                total += count
                f.write(f"{category}: {count} documents\n")
            
            f.write("-" * 30 + "\n")
            f.write(f"Total: {total} documents\n")
        
        os.chmod(summary_file, 0o644)
        logger.info(f"Summary saved to {summary_file}")
        
        # Clean up progress file after successful completion
        if self.progress_file.exists() and len(self.processed_terms) == len(self.build_search_terms()):
            self.progress_file.unlink()
            logger.info("Search completed successfully! Progress file removed.")

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='LexML Transport Legislation Search')
    parser.add_argument('--output', '-o', help='Output directory (default: ~/lexml_results)')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume from previous search')
    
    args = parser.parse_args()
    
    logger.info("Starting LexML Transport Legislation Search")
    logger.info("=" * 50)
    logger.info(f"WSL Environment: {os.environ.get('WSL_DISTRO_NAME', 'Not detected')}")
    
    searcher = LexMLSearcher(output_dir=args.output, resume=args.resume)
    
    try:
        # Perform searches
        searcher.search_all_terms()
        
        # Export results
        searcher.export_to_csv()
        
        logger.info("Search completed!")
        
    except KeyboardInterrupt:
        logger.info("\nSearch interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        searcher.save_progress()

if __name__ == "__main__":
    main()
