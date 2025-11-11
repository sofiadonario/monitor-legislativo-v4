#!/usr/bin/env python3
"""
LexML Web Scraper Final - Versão Corrigida
Acesso à base completa via interface web

Baseado na descoberta de que a API SRU retorna apenas 0,6% da base real
Interface web tem 6.813+ documentos vs 42 da API
"""

import requests
import time
import csv
import re
import argparse
from urllib.parse import urlencode
from bs4 import BeautifulSoup
import logging
from datetime import datetime
import json
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LexMLWebScraperFinal:
    """
    Web scraper final corrigido para acessar base completa do LexML
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Referer': 'https://www.lexml.gov.br/'
        })
        
        self.base_url = 'https://www.lexml.gov.br/busca/search'
        self.results = []
        self.stats = {
            'total_found': 0,
            'total_collected': 0,
            'pages_processed': 0,
            'errors': 0,
            'start_time': datetime.now()
        }
    
    def search_term(self, search_term, max_results=None):
        """
        Busca um termo específico com acesso à base completa
        """
        
        logging.info(f"🔍 Iniciando busca para: '{search_term}'")
        
        # Primeira requisição para obter total de resultados
        total_results = self._get_total_results(search_term)
        
        if total_results == 0:
            logging.warning(f"Nenhum resultado encontrado para '{search_term}'")
            return []
        
        logging.info(f"📊 Total de resultados disponíveis: {total_results:,}")
        
        # Limita se especificado
        if max_results and max_results < total_results:
            total_results = max_results
            logging.info(f"🎯 Limitando coleta a: {total_results:,} resultados")
        
        # Coleta com paginação
        results = self._collect_paginated_results(search_term, total_results)
        
        logging.info(f"✅ Coleta concluída: {len(results):,} documentos")
        return results
    
    def _get_total_results(self, search_term):
        """
        Obtém o número total de resultados disponíveis
        """
        
        params = {
            'keyword': search_term,
            'f1-tipoDocumento': ''
        }
        
        try:
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Procura por "Resultados: X Itens"
            results_text = soup.find(text=re.compile(r'Resultados:\\s*\\d+\\s*Itens'))
            if results_text:
                numbers = re.findall(r'\\d+', results_text)
                if numbers:
                    return int(numbers[0])
            
            # Fallback: procura em outros elementos
            for element in soup.find_all(text=True):
                if 'resultados' in element.lower() and 'itens' in element.lower():
                    numbers = re.findall(r'\\d+', element)
                    if numbers:
                        return int(numbers[0])
            
            return 0
            
        except Exception as e:
            logging.error(f"Erro ao obter total de resultados: {e}")
            return 0
    
    def _collect_paginated_results(self, search_term, total_results):
        """
        Coleta resultados com paginação completa
        """
        
        results = []
        page = 1
        results_per_page = 20  # Padrão da interface web
        total_pages = (total_results + results_per_page - 1) // results_per_page
        
        logging.info(f"📄 Processando {total_pages} páginas...")
        
        while len(results) < total_results:
            try:
                start_record = (page - 1) * results_per_page + 1
                
                logging.info(f"Página {page}/{total_pages} (registros {start_record}-{min(start_record + results_per_page - 1, total_results)})")
                
                page_results = self._extract_page_results(search_term, start_record, results_per_page)
                
                if not page_results:
                    logging.warning(f"Página {page}: Nenhum resultado extraído - finalizando")
                    break
                
                results.extend(page_results)
                self.stats['pages_processed'] += 1
                
                logging.info(f"  ✅ {len(page_results)} resultados extraídos (total: {len(results)})")
                
                # Controle de rate limiting
                time.sleep(1)
                
                page += 1
                
                # Verifica se chegou ao fim
                if len(page_results) < results_per_page:
                    logging.info("Última página detectada")
                    break
                    
            except Exception as e:
                logging.error(f"Erro na página {page}: {e}")
                self.stats['errors'] += 1
                
                # Tenta continuar na próxima página
                page += 1
                if self.stats['errors'] > 5:
                    logging.error("Muitos erros - interrompendo coleta")
                    break
        
        return results
    
    def _extract_page_results(self, search_term, start_record, max_records):
        """
        Extrai resultados de uma página específica
        """
        
        params = {
            'keyword': search_term,
            'f1-tipoDocumento': '',
            'startRecord': start_record,
            'maximumRecords': max_records
        }
        
        response = self.session.get(self.base_url, params=params, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extrai resultados baseado na estrutura HTML real identificada
        results = []
        
        # Procura por tabelas de resultados (estrutura principal)
        result_tables = soup.find_all('table')
        
        for table in result_tables:
            rows = table.find_all('tr')
            
            current_result = None
            
            for row in rows:
                cells = row.find_all(['td', 'th'])
                
                if len(cells) >= 2:
                    # Verifica se é início de novo resultado (tem número)
                    first_cell = cells[0].get_text(strip=True)
                    
                    if first_cell.isdigit():
                        # Salva resultado anterior se existir
                        if current_result and self._is_valid_result(current_result):
                            results.append(current_result)
                        
                        # Inicia novo resultado
                        current_result = self._create_empty_result(search_term)
                        current_result['result_number'] = int(first_cell)
                    
                    # Processa células da linha atual
                    if current_result:
                        self._process_row_cells(cells, current_result)
            
            # Adiciona último resultado se válido
            if current_result and self._is_valid_result(current_result):
                results.append(current_result)
        
        return results
    
    def _create_empty_result(self, search_term):
        """
        Cria estrutura vazia para um resultado
        """
        
        return {
            'search_term': search_term,
            'date_searched': datetime.now().strftime('%Y-%m-%d'),
            'url': '',
            'title': '',
            'urn': '',
            'urn_type': '',
            'country': 'br',
            'state': '',
            'municipality': '',
            'justice': '',
            'region': '',
            'court_class': '',
            'document_type_full': '',
            'enacting_date': '',
            'document_description': '',
            'document_summary': '',
            'result_number': 0
        }
    
    def _process_row_cells(self, cells, result):
        """
        Processa células de uma linha para extrair dados
        """
        
        for cell in cells:
            cell_text = cell.get_text(strip=True)
            
            # Localidade
            if 'Localidade' in cell_text:
                if 'Brasil' in cell_text:
                    result['country'] = 'br'
                # Extrai estado se presente
                parts = cell_text.split()
                for part in parts:
                    if len(part) == 2 and part.isupper():
                        result['state'] = part.lower()
            
            # Autoridade
            elif 'Autoridade' in cell_text:
                authority = cell_text.replace('Autoridade', '').strip()
                result['justice'] = authority
                
                if 'Federal' in authority:
                    result['court_class'] = 'Federal'
                elif 'Estadual' in authority:
                    result['court_class'] = 'Estadual'
                elif 'Municipal' in authority:
                    result['court_class'] = 'Municipal'
            
            # Título
            elif 'Título' in cell_text:
                title_link = cell.find('a')
                if title_link:
                    result['title'] = title_link.get_text(strip=True)
                    href = title_link.get('href', '')
                    if href:
                        result['url'] = href if href.startswith('http') else f"https://www.lexml.gov.br{href}"
                else:
                    # Título sem link
                    title_text = cell_text.replace('Título', '').strip()
                    if title_text:
                        result['title'] = title_text
            
            # Data
            elif 'Data' in cell_text:
                date_match = re.search(r'(\\d{2}/\\d{2}/\\d{4})', cell_text)
                if date_match:
                    date_str = date_match.group(1)
                    result['enacting_date'] = self._convert_date_format(date_str)
            
            # URN
            elif 'URN' in cell_text:
                urn_match = re.search(r'urn:lex:[^\\s]+', cell_text)
                if urn_match:
                    result['urn'] = urn_match.group(0)
                    result['urn_type'] = self._classify_urn_type(result['urn'])
            
            # Ementa
            elif 'Ementa' in cell_text and len(cell_text) > 50:
                ementa = cell_text.replace('Ementa', '').strip()
                result['document_summary'] = ementa
            
            # Tipo
            elif 'Tipo' in cell_text:
                doc_type = cell_text.replace('Tipo', '').strip()
                result['document_type_full'] = doc_type
            
            # Descrição longa (pode ser ementa sem rótulo)
            elif len(cell_text) > 100 and not any(keyword in cell_text for keyword in ['Localidade', 'Autoridade', 'Título', 'Data', 'URN', 'Tipo']):
                if not result['document_summary']:  # Só preenche se ainda não tem ementa
                    result['document_summary'] = cell_text[:500] + '...' if len(cell_text) > 500 else cell_text
    
    def _is_valid_result(self, result):
        """
        Verifica se um resultado é válido
        """
        
        return bool(result.get('title') or result.get('urn') or result.get('document_summary'))
    
    def _classify_urn_type(self, urn):
        """
        Classifica tipo de documento baseado na URN
        """
        
        if not urn:
            return 'unknown'
        
        urn_lower = urn.lower()
        
        # Legislação
        if any(term in urn_lower for term in ['lei', 'decreto', 'portaria', 'resolucao', 'instrucao.normativa', 'medida.provisoria']):
            return 'legislation'
        
        # Jurisprudência
        if any(term in urn_lower for term in ['acordao', 'sentenca', 'decisao', 'recurso', 'agravo', 'apelacao']):
            return 'jurisprudence'
        
        # Doutrina
        if any(term in urn_lower for term in ['artigo', 'livro', 'tese', 'dissertacao', 'parecer']):
            return 'doctrine'
        
        return 'other'
    
    def _convert_date_format(self, date_str):
        """
        Converte data de DD/MM/AAAA para AAAA-MM-DD
        """
        
        try:
            if '/' in date_str:
                day, month, year = date_str.split('/')
                return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
            return date_str
        except:
            return ''
    
    def save_results(self, results, filename=None):
        """
        Salva resultados em CSV
        """
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'lexml_final_results_{timestamp}.csv'
        
        fieldnames = [
            'search_term', 'date_searched', 'url', 'title', 'urn', 'urn_type',
            'country', 'state', 'municipality', 'justice', 'region', 'court_class',
            'document_type_full', 'enacting_date', 'document_description', 'document_summary'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Remove campos internos
                clean_result = {k: v for k, v in result.items() if k in fieldnames}
                # Garante que todos os campos existem
                complete_result = {field: clean_result.get(field, '') for field in fieldnames}
                writer.writerow(complete_result)
        
        logging.info(f"📁 Resultados salvos em: {filename}")
        return filename
    
    def generate_report(self, results):
        """
        Gera relatório da coleta
        """
        
        print(f"\\n" + "=" * 60)
        print(f"📊 RELATÓRIO FINAL DA COLETA")
        print(f"=" * 60)
        
        print(f"🔍 Total coletado: {len(results):,} documentos")
        print(f"📄 Páginas processadas: {self.stats['pages_processed']}")
        print(f"❌ Erros: {self.stats['errors']}")
        
        if results:
            # Análise por tipo
            type_counts = {}
            for result in results:
                doc_type = result.get('urn_type', 'unknown')
                type_counts[doc_type] = type_counts.get(doc_type, 0) + 1
            
            print(f"\\n📋 Por tipo de documento:")
            for doc_type, count in sorted(type_counts.items()):
                print(f"  {doc_type}: {count:,}")
            
            # Análise temporal
            years = {}
            for result in results:
                date_str = result.get('enacting_date', '')
                if date_str and len(date_str) >= 4:
                    year = date_str[:4]
                    if year.isdigit():
                        years[year] = years.get(year, 0) + 1
            
            if years:
                print(f"\\n📅 Por década (top 10):")
                for year, count in sorted(years.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {year}: {count:,}")


def main():
    """
    Função principal com argumentos de linha de comando
    """
    
    parser = argparse.ArgumentParser(description='LexML Web Scraper Final - Acesso à base completa')
    parser.add_argument('--term', type=str, help='Termo específico para buscar')
    parser.add_argument('--max-results', type=int, help='Máximo de resultados por termo')
    parser.add_argument('--output', type=str, help='Arquivo de saída')
    
    args = parser.parse_args()
    
    scraper = LexMLWebScraperFinal()
    
    # Termo padrão se não especificado
    search_term = args.term or 'transporte de carga'
    
    print(f"🚀 LEXML WEB SCRAPER FINAL")
    print(f"Termo: {search_term}")
    print(f"Limite: {args.max_results or 'Sem limite'}")
    print("=" * 60)
    
    # Executa busca
    results = scraper.search_term(search_term, args.max_results)
    
    # Salva resultados
    filename = scraper.save_results(results, args.output)
    
    # Gera relatório
    scraper.generate_report(results)
    
    print(f"\\n🎯 COLETA CONCLUÍDA!")
    print(f"Arquivo: {filename}")
    print(f"Total: {len(results):,} documentos")


if __name__ == "__main__":
    main()

