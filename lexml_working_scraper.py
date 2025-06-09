#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LexML Web Scraper - Complete Working Version
This is the tested and working scraper for all transport terms
"""

import requests
import re
import csv
import time
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode
from pathlib import Path

class LexMLWebScraperComplete:
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br"
        self.search_url = "https://www.lexml.gov.br/busca/search"
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 KHTML, like Gecko Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Output directory
        self.output_dir = Path.home() / 'lexml_results'
        self.output_dir.mkdir(exist_ok=True)
        
    def search_term(self, term, max_pages=3):
        """Search for a term and extract results"""
        results = []
        
        for page in range(1, max_pages + 1):
            params = {
                'keyword': term,
                'startDoc': (page - 1) * 20 + 1
            }
            
            try:
                response = self.session.get(self.search_url, params=params, timeout=15)
                
                if response.status_code == 200:
                    # Parse results
                    page_results = self._parse_results(response.text, term)
                    results.extend(page_results)
                    
                    if len(page_results) == 0:
                        break
                    
                    time.sleep(1)
                else:
                    break
                    
            except Exception as e:
                print(f"  Error: {e}")
                break
                
        return results
    
    def _parse_results(self, html, search_term):
        """Parse search results from HTML"""
        results = []
        
        # Look for URN links
        urn_pattern = r'<a[^>]+href="(/urn/urn:lex:br[^"]+)"[^>]*>([^<]+)</a>'
        matches = re.findall(urn_pattern, html)
        
        for url_part, title in matches:
            result = {
                'search_term': search_term,
                'date_searched': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'url': self.base_url + url_part,
                'title': re.sub(r'<[^>]+>', '', title).strip(),
                'urn': url_part.replace('/urn/', '')
            }
            results.append(result)
        
        return results
    
    def get_all_transport_terms(self):
        """Complete list of transport terms"""
        return [
            # General transport terms
            "transporte de carga",
            "transporte rodoviário de carga",
            "logística de carga",
            "frete",
            "fretamento",
            "caminhão",
            "caminhões",
            "veículos pesados",
            "veículos de carga",
            "veículos comerciais",
            "transporte de mercadorias",
            "modal rodoviário",
            
            # Fuels and energy
            "gás natural veicular",
            "biometano",
            "diesel",
            "biodiesel",
            "diesel verde",
            "combustível sustentável",
            "hidrogênio",
            "etanol",
            "SAF",
            "carga aérea",
            "combustível",
            
            # Energy efficiency and emissions
            "eficiência energética",
            "emissões",
            "descarbonização",
            "gases de efeito estufa",
            "rotulagem veicular",
            "consumo de combustível",
            "emissões veiculares",
            
            # Technology and innovation
            "tecnologias assistivas",
            "veículos autônomos",
            "telemetria",
            "rastreamento",
            "motorização",
            "conversão",
            "tecnologia veicular",
            
            # Infrastructure
            "postos de abastecimento",
            "infraestrutura",
            "combustíveis alternativos",
            "terminais de carga",
            "centros de distribuição",
            "armazéns",
            "logística",
            
            # Regulation
            "CONTRAN",
            "ANTT",
            "registro transportador",
            "habilitação",
            "licenciamento",
            "RNTRC",
            "segurança veicular",
            "regulamentação transporte",
            
            # Incentives and taxation
            "IPI",
            "ICMS",
            "incentivo fiscal",
            "isenção",
            "benefício tributário",
            "financiamento",
            "IPI caminhão",
            "ICMS transporte",
            
            # Rota 2030 and Paten
            "Rota 2030",
            "Paten",
            "mobilidade e logística",
            "transição energética",
            "desenvolvimento sustentável",
            "P&D",
            "pesquisa e desenvolvimento",
            "inovação automotiva",
            
            # Machinery and equipment
            "máquinas agrícolas",
            "implementos rodoviários",
            "reboque",
            "semi-reboque",
            "carreta",
            "bitrem",
            "rodotrem",
            "equipamentos de transporte",
            
            # Operations and services
            "transportador autônomo",
            "empresa de transporte",
            "operador logístico",
            "embarcador",
            "terceirização",
            "contrato de frete",
            "tabela de frete",
            
            # Additional terms
            "transporte",
            "veículo",
            "rodoviário",
            "transportador",
            "motorista",
            "carga pesada",
            "transporte pesado",
            "frota",
            "veículo pesado"
        ]
    
    def run_complete_search(self):
        """Run search for all terms"""
        print("\nLexML Transport Legislation Search")
        print("=" * 50)
        
        terms = self.get_all_transport_terms()
        print(f"Searching {len(terms)} terms...")
        
        start_time = datetime.now()
        
        for i, term in enumerate(terms, 1):
            print(f"\n[{i}/{len(terms)}] Searching: '{term}'")
            
            results = self.search_term(term, max_pages=2)
            self.results.extend(results)
            
            print(f"  Found {len(results)} results")
            
            time.sleep(1.5)  # Rate limiting
        
        print(f"\n\nSearch completed in {(datetime.now() - start_time).seconds} seconds")
        print(f"Total results: {len(self.results)}")
        
        # Remove duplicates
        self.deduplicate_results()
        
        # Save results
        self.save_results()
    
    def deduplicate_results(self):
        """Remove duplicate results based on URL"""
        print("\nRemoving duplicates...")
        seen_urls = set()
        unique_results = []
        
        for result in self.results:
            url = result.get('url', '')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(result)
        
        removed = len(self.results) - len(unique_results)
        self.results = unique_results
        
        if removed > 0:
            print(f"Removed {removed} duplicates")
    
    def save_results(self):
        """Save results to CSV and create summary"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if self.results:
            # Save CSV
            csv_file = self.output_dir / f'lexml_transport_results_{timestamp}.csv'
            
            with open(csv_file, 'w', newline='', encoding='utf-8-sig') as f:
                fieldnames = ['search_term', 'date_searched', 'url', 'title', 'urn']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    writer.writerow(result)
            
            print(f"\n✓ Results saved to: {csv_file}")
            
            # Create summary
            summary_file = self.output_dir / f'search_summary_{timestamp}.txt'
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("LexML Transport Search Summary\n")
                f.write("=" * 60 + "\n")
                f.write(f"Search Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Results: {len(self.results)}\n\n")
                
                # Count by search term
                term_counts = {}
                for result in self.results:
                    term = result.get('search_term', 'Unknown')
                    term_counts[term] = term_counts.get(term, 0) + 1
                
                f.write("Results by Search Term:\n")
                f.write("-" * 40 + "\n")
                for term, count in sorted(term_counts.items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        f.write(f"{term}: {count} results\n")
            
            print(f"✓ Summary saved to: {summary_file}")
            
            # Print stats
            print(f"\nSearch Statistics:")
            print(f"- Total unique results: {len(self.results)}")
            print(f"- Terms with results: {len([t for t, c in term_counts.items() if c > 0])}")
            print(f"- Files saved in: {self.output_dir}")
        else:
            print("\n✗ No results found")

if __name__ == "__main__":
    scraper = LexMLWebScraperComplete()
    scraper.run_complete_search()
