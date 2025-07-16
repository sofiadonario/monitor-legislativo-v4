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
from urllib.parse import urlencode, urljoin
from bs4 import BeautifulSoup
import logging
from datetime import datetime
import json
import os
from typing import Dict, List, Optional, Tuple

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
        
        # Carregar termos de busca do arquivo
        self.search_terms = self._load_search_terms()
    
    def _load_search_terms(self) -> List[str]:
        """Carrega termos de busca do arquivo de configuração"""
        terms_file = os.path.join(os.path.dirname(__file__), '..', 'lexml_overview', 'Termos de Busca para Monitor Legislativo - Transporte de Carga.txt')
        
        try:
            with open(terms_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Extrair termos da estrutura do arquivo
            terms = []
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if line.startswith('* '):
                    # Extrair termo entre aspas ou até AND
                    term = line[2:].strip()
                    if '"' in term:
                        # Extrair termo entre aspas
                        matches = re.findall(r'"([^"]*)"', term)
                        terms.extend(matches)
                    else:
                        # Extrair termo até AND ou EOF
                        term = term.split(' AND ')[0].strip()
                        if term and not term.startswith('('):
                            terms.append(term)
            
            # Remover duplicatas e filtrar
            unique_terms = list(set(terms))
            filtered_terms = [term for term in unique_terms if len(term) > 2 and term.replace(' ', '').isalpha()]
            
            logger.info(f"Carregados {len(filtered_terms)} termos de busca")
            return filtered_terms
            
        except FileNotFoundError:
            logger.warning("Arquivo de termos não encontrado, usando termos padrão")
            return ["transporte de carga", "transporte rodoviário", "caminhão", "frete", "logística"]
    
    def search_term(self, search_term: str, max_results: Optional[int] = None) -> List[Dict]:
        """
        Busca um termo específico com acesso à base completa
        """
        
        logger.info(f"🔍 Iniciando busca para: '{search_term}'")
        
        # Primeira requisição para obter total de resultados
        total_results = self._get_total_results(search_term)
        
        if total_results == 0:
            logger.warning(f"Nenhum resultado encontrado para '{search_term}'")
            return []
        
        logger.info(f"📊 Total de resultados disponíveis: {total_results:,}")
        
        # Limita se especificado
        if max_results and max_results < total_results:
            total_results = max_results
            logger.info(f"🎯 Limitando coleta a: {total_results:,} resultados")
        
        # Coleta com paginação
        results = self._collect_paginated_results(search_term, total_results)
        
        logger.info(f"✅ Coleta concluída: {len(results):,} documentos")
        return results
    
    def _get_total_results(self, search_term: str) -> int:
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
            
            # Procura por "Resultados: X Itens" ou padrões similares
            patterns = [
                r'Resultados:\s*(\d+)\s*Itens',
                r'(\d+)\s*resultados?\s*encontrados?',
                r'Total:\s*(\d+)',
                r'(\d+)\s*documentos?'
            ]
            
            text_content = soup.get_text()
            
            for pattern in patterns:
                match = re.search(pattern, text_content, re.IGNORECASE)
                if match:
                    return int(match.group(1))
            
            # Fallback: contar elementos de resultado na página
            result_elements = soup.find_all(['tr', 'div'], class_=re.compile(r'result|item|documento'))
            if result_elements:
                logger.info(f"Fallback: encontrados {len(result_elements)} elementos por página")
                return len(result_elements) * 50  # Estimativa conservadora
            
            return 0
            
        except Exception as e:
            logger.error(f"Erro ao obter total de resultados: {e}")
            return 0
    
    def _collect_paginated_results(self, search_term: str, total_results: int) -> List[Dict]:
        """
        Coleta resultados com paginação completa
        """
        
        results = []
        page = 1
        results_per_page = 20  # Padrão da interface web
        total_pages = (total_results + results_per_page - 1) // results_per_page
        
        logger.info(f"📄 Processando {total_pages} páginas...")
        
        while len(results) < total_results:
            try:
                start_record = (page - 1) * results_per_page + 1
                
                logger.info(f"Página {page}/{total_pages} (registros {start_record}-{min(start_record + results_per_page - 1, total_results)})")
                
                page_results = self._extract_page_results(search_term, start_record, results_per_page)
                
                if not page_results:
                    logger.warning(f"Página {page}: Nenhum resultado extraído - finalizando")
                    break
                
                results.extend(page_results)
                self.stats['pages_processed'] += 1
                
                logger.info(f"  ✅ {len(page_results)} resultados extraídos (total: {len(results)})")
                
                # Controle de rate limiting
                time.sleep(1)
                
                page += 1
                
                # Verifica se chegou ao fim
                if len(page_results) < results_per_page:
                    logger.info("Última página detectada")
                    break
                    
            except Exception as e:
                logger.error(f"Erro na página {page}: {e}")
                self.stats['errors'] += 1
                
                # Tenta continuar na próxima página
                page += 1
                if self.stats['errors'] > 5:
                    logger.error("Muitos erros - interrompendo coleta")
                    break
        
        return results
    
    def _extract_page_results(self, search_term: str, start_record: int, max_records: int) -> List[Dict]:
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
        
        # Procura por diferentes estruturas possíveis
        result_containers = (
            soup.find_all('table') +
            soup.find_all('div', class_=re.compile(r'result|item|documento')) +
            soup.find_all('tr', class_=re.compile(r'result|item|documento'))
        )
        
        current_result = None
        
        for container in result_containers:
            # Para tabelas
            if container.name == 'table':
                rows = container.find_all('tr')
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    if len(cells) >= 2:
                        result = self._extract_result_from_cells(cells, search_term)
                        if result and self._is_valid_result(result):
                            results.append(result)
            
            # Para divs e outros containers
            else:
                result = self._extract_result_from_container(container, search_term)
                if result and self._is_valid_result(result):
                    results.append(result)
        
        # Se não encontrou resultados, tenta estratégia alternativa
        if not results:
            results = self._extract_alternative_format(soup, search_term)
        
        return results
    
    def _extract_result_from_cells(self, cells: List, search_term: str) -> Optional[Dict]:
        """
        Extrai resultado de células de tabela
        """
        
        result = self._create_empty_result(search_term)
        
        for cell in cells:
            cell_text = cell.get_text(strip=True)
            
            # Localidade
            if any(keyword in cell_text.lower() for keyword in ['localidade', 'jurisdiction', 'brasil']):
                result['country'] = 'br'
                # Extrair estado se presente
                parts = cell_text.split()
                for part in parts:
                    if len(part) == 2 and part.isupper():
                        result['state'] = part.lower()
            
            # Autoridade
            elif any(keyword in cell_text.lower() for keyword in ['autoridade', 'authority', 'órgão']):
                authority = re.sub(r'autoridade:?', '', cell_text.lower()).strip()
                result['justice'] = authority
                
                if 'federal' in authority:
                    result['court_class'] = 'Federal'
                elif 'estadual' in authority:
                    result['court_class'] = 'Estadual'
                elif 'municipal' in authority:
                    result['court_class'] = 'Municipal'
            
            # Título
            elif any(keyword in cell_text.lower() for keyword in ['título', 'title', 'nome']):
                title_link = cell.find('a')
                if title_link:
                    result['title'] = title_link.get_text(strip=True)
                    href = title_link.get('href', '')
                    if href:
                        result['url'] = href if href.startswith('http') else urljoin('https://www.lexml.gov.br', href)
                else:
                    title_text = re.sub(r'título:?', '', cell_text.lower()).strip()
                    if title_text:
                        result['title'] = title_text
            
            # Data
            elif any(keyword in cell_text.lower() for keyword in ['data', 'date']):
                date_match = re.search(r'(\d{2}/\d{2}/\d{4})', cell_text)
                if date_match:
                    date_str = date_match.group(1)
                    result['enacting_date'] = self._convert_date_format(date_str)
            
            # URN
            elif 'urn:lex:' in cell_text.lower():
                urn_match = re.search(r'urn:lex:[^\s]+', cell_text)
                if urn_match:
                    result['urn'] = urn_match.group(0)
                    result['urn_type'] = self._classify_urn_type(result['urn'])
            
            # Ementa/Resumo
            elif any(keyword in cell_text.lower() for keyword in ['ementa', 'resumo', 'descrição']) and len(cell_text) > 50:
                ementa = re.sub(r'ementa:?', '', cell_text.lower()).strip()
                result['document_summary'] = ementa
            
            # Tipo de documento
            elif any(keyword in cell_text.lower() for keyword in ['tipo', 'type', 'categoria']):
                doc_type = re.sub(r'tipo:?', '', cell_text.lower()).strip()
                result['document_type_full'] = doc_type
        
        return result if self._is_valid_result(result) else None
    
    def _extract_result_from_container(self, container, search_term: str) -> Optional[Dict]:
        """
        Extrai resultado de um container div
        """
        
        result = self._create_empty_result(search_term)
        container_text = container.get_text()
        
        # Extrair informações básicas
        result['title'] = self._extract_title(container)
        result['url'] = self._extract_url(container)
        result['urn'] = self._extract_urn(container_text)
        result['enacting_date'] = self._extract_date(container_text)
        result['document_summary'] = self._extract_summary(container_text)
        result['document_type_full'] = self._extract_document_type(container_text)
        
        if result['urn']:
            result['urn_type'] = self._classify_urn_type(result['urn'])
        
        return result if self._is_valid_result(result) else None
    
    def _extract_alternative_format(self, soup: BeautifulSoup, search_term: str) -> List[Dict]:
        """
        Estratégia alternativa para extrair resultados
        """
        
        results = []
        
        # Procurar por links que contenham URNs
        links = soup.find_all('a', href=re.compile(r'urn:lex:'))
        
        for link in links:
            result = self._create_empty_result(search_term)
            result['title'] = link.get_text(strip=True)
            result['url'] = link.get('href', '')
            
            # Extrair URN do href
            urn_match = re.search(r'urn:lex:[^\s&]+', result['url'])
            if urn_match:
                result['urn'] = urn_match.group(0)
                result['urn_type'] = self._classify_urn_type(result['urn'])
            
            if self._is_valid_result(result):
                results.append(result)
        
        return results
    
    def _extract_title(self, container) -> str:
        """Extrai título do container"""
        title_selectors = ['h1', 'h2', 'h3', '.title', '.titulo', 'strong', 'b']
        
        for selector in title_selectors:
            element = container.select_one(selector)
            if element:
                return element.get_text(strip=True)
        
        # Fallback: primeiro link
        link = container.find('a')
        if link:
            return link.get_text(strip=True)
        
        return ""
    
    def _extract_url(self, container) -> str:
        """Extrai URL do container"""
        link = container.find('a')
        if link:
            href = link.get('href', '')
            return href if href.startswith('http') else urljoin('https://www.lexml.gov.br', href)
        return ""
    
    def _extract_urn(self, text: str) -> str:
        """Extrai URN do texto"""
        urn_match = re.search(r'urn:lex:[^\s]+', text)
        return urn_match.group(0) if urn_match else ""
    
    def _extract_date(self, text: str) -> str:
        """Extrai data do texto"""
        date_match = re.search(r'(\d{2}/\d{2}/\d{4})', text)
        if date_match:
            return self._convert_date_format(date_match.group(1))
        return ""
    
    def _extract_summary(self, text: str) -> str:
        """Extrai resumo/ementa do texto"""
        # Remover elementos desnecessários
        clean_text = re.sub(r'(URN|Data|Tipo|Autoridade):[^\n]*', '', text)
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()
        
        if len(clean_text) > 100:
            return clean_text[:500] + '...' if len(clean_text) > 500 else clean_text
        
        return clean_text
    
    def _extract_document_type(self, text: str) -> str:
        """Extrai tipo de documento do texto"""
        type_patterns = [
            r'Tipo:\s*([^\n]+)',
            r'(Lei|Decreto|Portaria|Resolução|Instrução Normativa|Medida Provisória)',
            r'(Acórdão|Decisão|Sentença|Súmula)'
        ]
        
        for pattern in type_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return ""
    
    def _create_empty_result(self, search_term: str) -> Dict:
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
    
    def _is_valid_result(self, result: Dict) -> bool:
        """
        Verifica se um resultado é válido
        """
        
        return bool(result.get('title') or result.get('urn') or result.get('document_summary'))
    
    def _classify_urn_type(self, urn: str) -> str:
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
    
    def _convert_date_format(self, date_str: str) -> str:
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
    
    def search_all_terms(self, max_results_per_term: Optional[int] = None) -> List[Dict]:
        """
        Busca todos os termos carregados
        """
        
        all_results = []
        
        for i, term in enumerate(self.search_terms, 1):
            logger.info(f"📝 Processando termo {i}/{len(self.search_terms)}: {term}")
            
            try:
                term_results = self.search_term(term, max_results_per_term)
                all_results.extend(term_results)
                
                logger.info(f"  ✅ {len(term_results)} resultados coletados")
                
                # Pausa entre termos
                if i < len(self.search_terms):
                    time.sleep(2)
                    
            except Exception as e:
                logger.error(f"  ❌ Erro ao processar termo '{term}': {e}")
                continue
        
        # Remover duplicatas baseado em URN
        unique_results = []
        seen_urns = set()
        
        for result in all_results:
            urn = result.get('urn', '')
            if urn and urn not in seen_urns:
                seen_urns.add(urn)
                unique_results.append(result)
            elif not urn:
                # Para resultados sem URN, usar título como identificador
                title = result.get('title', '')
                if title and title not in seen_urns:
                    seen_urns.add(title)
                    unique_results.append(result)
        
        logger.info(f"🔍 Total de resultados únicos: {len(unique_results)}")
        return unique_results
    
    def save_results(self, results: List[Dict], filename: Optional[str] = None) -> str:
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
        
        # Garantir que o diretório existe
        os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Remove campos internos
                clean_result = {k: v for k, v in result.items() if k in fieldnames}
                # Garante que todos os campos existem
                complete_result = {field: clean_result.get(field, '') for field in fieldnames}
                writer.writerow(complete_result)
        
        logger.info(f"📁 Resultados salvos em: {filename}")
        return filename
    
    def save_results_json(self, results: List[Dict], filename: Optional[str] = None) -> str:
        """
        Salva resultados em JSON
        """
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'lexml_final_results_{timestamp}.json'
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        logger.info(f"📁 Resultados salvos em JSON: {filename}")
        return filename
    
    def generate_report(self, results: List[Dict]):
        """
        Gera relatório da coleta
        """
        
        print(f"\n" + "=" * 60)
        print(f"📊 RELATÓRIO FINAL DA COLETA")
        print(f"=" * 60)
        
        print(f"🔍 Total coletado: {len(results):,} documentos")
        print(f"📄 Páginas processadas: {self.stats['pages_processed']}")
        print(f"❌ Erros: {self.stats['errors']}")
        print(f"⏱️ Tempo total: {datetime.now() - self.stats['start_time']}")
        
        if results:
            # Análise por tipo
            type_counts = {}
            for result in results:
                doc_type = result.get('urn_type', 'unknown')
                type_counts[doc_type] = type_counts.get(doc_type, 0) + 1
            
            print(f"\n📋 Por tipo de documento:")
            for doc_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
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
                print(f"\n📅 Por década (top 10):")
                sorted_years = sorted(years.items(), key=lambda x: x[1], reverse=True)[:10]
                for year, count in sorted_years:
                    print(f"  {year}: {count:,}")
            
            # Análise por termo de busca
            term_counts = {}
            for result in results:
                term = result.get('search_term', 'unknown')
                term_counts[term] = term_counts.get(term, 0) + 1
            
            print(f"\n🔍 Por termo de busca (top 10):")
            sorted_terms = sorted(term_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for term, count in sorted_terms:
                print(f"  {term}: {count:,}")
        
        print(f"\n{'=' * 60}")


def main():
    """
    Função principal com argumentos de linha de comando
    """
    
    parser = argparse.ArgumentParser(description='LexML Web Scraper Final - Acesso à base completa')
    parser.add_argument('--term', type=str, help='Termo específico para buscar')
    parser.add_argument('--all-terms', action='store_true', help='Buscar todos os termos do arquivo')
    parser.add_argument('--max-results', type=int, help='Máximo de resultados por termo')
    parser.add_argument('--output', type=str, help='Arquivo de saída CSV')
    parser.add_argument('--output-json', type=str, help='Arquivo de saída JSON')
    parser.add_argument('--incremental', action='store_true', help='Coleta incremental')
    parser.add_argument('--daily', action='store_true', help='Modo diário')
    
    args = parser.parse_args()
    
    scraper = LexMLWebScraperFinal()
    
    print(f"🚀 LEXML WEB SCRAPER FINAL")
    print(f"=" * 60)
    
    results = []
    
    if args.all_terms:
        print(f"🔍 Buscando todos os termos ({len(scraper.search_terms)} termos)")
        print(f"📊 Limite por termo: {args.max_results or 'Sem limite'}")
        results = scraper.search_all_terms(args.max_results)
    else:
        search_term = args.term or 'transporte de carga'
        print(f"🔍 Termo: {search_term}")
        print(f"📊 Limite: {args.max_results or 'Sem limite'}")
        results = scraper.search_term(search_term, args.max_results)
    
    if results:
        # Salvar resultados
        if args.output:
            scraper.save_results(results, args.output)
        else:
            csv_filename = scraper.save_results(results)
        
        if args.output_json:
            scraper.save_results_json(results, args.output_json)
        
        # Gerar relatório
        scraper.generate_report(results)
        
        print(f"\n🎯 COLETA CONCLUÍDA!")
        print(f"📊 Total: {len(results):,} documentos coletados")
    else:
        print(f"\n❌ Nenhum resultado encontrado")


if __name__ == "__main__":
    main()