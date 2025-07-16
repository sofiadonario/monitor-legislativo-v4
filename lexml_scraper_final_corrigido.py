#!/usr/bin/env python3
"""
LexML Web Scraper Final Corrigido
Baseado na descoberta da URL correta que funciona

Desenvolvido por: Manus AI
Data: 2025-07-14
Versão: Final - URL Corrigida
"""

import requests
import csv
import time
import re
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote_plus
from datetime import datetime
import json
import os
from typing import Dict, List, Optional, Tuple

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('lexml_scraper_final.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class LexMLScraperFinalCorrigido:
    """
    Web scraper final corrigido para LexML com URL correta
    """
    
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br"
        self.search_url = "https://www.lexml.gov.br/busca/search"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Estatísticas
        self.stats = {
            'total_documents': 0,
            'successful_extractions': 0,
            'failed_extractions': 0,
            'pages_processed': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Cache para evitar duplicatas
        self.processed_urns = set()
        
    def search_documents(self, search_term: str, max_results: Optional[int] = None) -> List[Dict]:
        """
        Busca documentos no LexML para um termo específico
        """
        logger.info(f"Iniciando busca por: '{search_term}'")
        self.stats['start_time'] = datetime.now()
        
        all_documents = []
        page = 1
        
        while True:
            logger.info(f"Processando página {page}")
            
            # Fazer requisição para a página
            documents_page = self._scrape_page(search_term, page)
            
            if not documents_page:
                logger.info(f"Nenhum documento encontrado na página {page}. Finalizando.")
                break
                
            all_documents.extend(documents_page)
            self.stats['pages_processed'] = page
            
            logger.info(f"Página {page}: {len(documents_page)} documentos extraídos")
            
            # Verificar se atingiu o limite
            if max_results and len(all_documents) >= max_results:
                all_documents = all_documents[:max_results]
                logger.info(f"Limite de {max_results} documentos atingido")
                break
                
            # Verificar se há próxima página
            if not self._has_next_page(search_term, page):
                logger.info("Não há mais páginas. Finalizando.")
                break
                
            page += 1
            time.sleep(2)  # Rate limiting mais conservador
            
        self.stats['end_time'] = datetime.now()
        self.stats['total_documents'] = len(all_documents)
        
        logger.info(f"Busca concluída: {len(all_documents)} documentos extraídos")
        return all_documents
    
    def _scrape_page(self, search_term: str, page: int) -> List[Dict]:
        """
        Extrai documentos de uma página específica
        """
        try:
            # Parâmetros da requisição - SEM page para primeira página
            if page == 1:
                params = {
                    'keyword': search_term,
                    'f1-tipoDocumento': ''
                }
            else:
                # Para páginas subsequentes, usar o padrão de navegação
                params = {
                    'keyword': search_term,
                    'f1-tipoDocumento': '',
                    'startDoc': (page - 1) * 20 + 1  # Assumindo 20 resultados por página
                }
            
            # Fazer requisição
            response = self.session.get(self.search_url, params=params, timeout=30)
            response.raise_for_status()
            
            logger.info(f"URL acessada: {response.url}")
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Verificar se há resultados
            results_text = soup.get_text()
            if "nenhum resultado encontrado" in results_text.lower():
                logger.warning(f"Nenhum resultado encontrado na página {page}")
                return []
            
            # Extrair documentos usando a estrutura identificada
            documents = self._extract_documents_from_soup(soup, search_term)
            
            return documents
            
        except Exception as e:
            logger.error(f"Erro ao processar página {page}: {str(e)}")
            return []
    
    def _extract_documents_from_soup(self, soup: BeautifulSoup, search_term: str) -> List[Dict]:
        """
        Extrai documentos do HTML usando a estrutura real identificada
        """
        documents = []
        
        try:
            # Procurar por tabelas que contêm os resultados
            tables = soup.find_all('table')
            
            # Procurar pela tabela que contém os resultados numerados
            results_table = None
            for table in tables:
                # Procurar por células que contêm números (1, 2, 3...)
                cells = table.find_all('td')
                for cell in cells:
                    text = cell.get_text(strip=True)
                    if text.isdigit() and 1 <= int(text) <= 20:
                        results_table = table
                        break
                if results_table:
                    break
            
            if not results_table:
                logger.warning("Tabela de resultados não encontrada")
                return documents
            
            logger.info("Tabela de resultados encontrada")
            
            # Extrair resultados da tabela
            rows = results_table.find_all('tr')
            current_document = None
            current_number = None
            
            for row in rows:
                cells = row.find_all('td')
                
                if len(cells) >= 3:
                    first_cell = cells[0].get_text(strip=True)
                    
                    # Verificar se é início de novo resultado
                    if first_cell.isdigit():
                        # Salvar documento anterior se existir
                        if current_document and current_number:
                            current_document['search_term'] = search_term
                            current_document['result_number'] = current_number
                            documents.append(self._finalize_document(current_document))
                            self.stats['successful_extractions'] += 1
                        
                        # Iniciar novo documento
                        current_number = int(first_cell)
                        current_document = {
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
                            'document_summary': ''
                        }
                        
                        logger.debug(f"Iniciando extração do resultado {current_number}")
                    
                    # Processar campos do documento atual
                    if current_document and len(cells) >= 3:
                        field_label = cells[1].get_text(strip=True)
                        field_value = cells[2].get_text(strip=True)
                        
                        # Mapear campos
                        self._map_field_to_document(current_document, field_label, field_value, cells[2])
            
            # Salvar último documento
            if current_document and current_number:
                current_document['search_term'] = search_term
                current_document['result_number'] = current_number
                documents.append(self._finalize_document(current_document))
                self.stats['successful_extractions'] += 1
                
        except Exception as e:
            logger.error(f"Erro na extração de documentos: {str(e)}")
            self.stats['failed_extractions'] += 1
            
        logger.info(f"Extraídos {len(documents)} documentos da página")
        return documents
    
    def _map_field_to_document(self, document: Dict, field_label: str, field_value: str, cell_element) -> None:
        """
        Mapeia campos extraídos para a estrutura do documento
        """
        try:
            if field_label == 'Localidade':
                self._process_localidade(document, field_value)
            elif field_label == 'Autoridade':
                self._process_autoridade(document, field_value)
            elif field_label == 'Título':
                self._process_titulo(document, field_value, cell_element)
            elif field_label == 'Data':
                self._process_data(document, field_value)
            elif field_label == 'Ementa':
                self._process_ementa(document, field_value)
            elif field_label == 'URN':
                self._process_urn(document, field_value)
            elif field_label == 'Tipo':
                self._process_tipo(document, field_value)
            elif field_label == 'Autor':
                self._process_autor(document, field_value)
            elif field_label == 'Assuntos':
                self._process_assuntos(document, field_value)
            elif field_label == 'Classificação':
                self._process_classificacao(document, field_value)
            else:
                logger.debug(f"Campo não mapeado: {field_label} = {field_value[:50]}")
                
        except Exception as e:
            logger.error(f"Erro no mapeamento do campo {field_label}: {str(e)}")
    
    def _process_localidade(self, document: Dict, value: str) -> None:
        """Processa campo Localidade"""
        document['country'] = 'br'
        
        if 'Distrito Federal' in value:
            document['state'] = 'DF'
            document['region'] = 'Distrital'
        elif value == 'Brasil':
            document['region'] = 'Federal'
        else:
            document['state'] = value
    
    def _process_autoridade(self, document: Dict, value: str) -> None:
        """Processa campo Autoridade"""
        document['justice'] = value
        
        if 'Congresso Nacional' in value:
            document['court_class'] = 'Legislativo Federal'
        elif 'STF' in value or 'Supremo' in value:
            document['court_class'] = 'STF'
        elif 'STJ' in value:
            document['court_class'] = 'STJ'
        elif 'Tribunal' in value:
            document['court_class'] = 'Tribunal'
        else:
            document['court_class'] = 'Outros'
    
    def _process_titulo(self, document: Dict, value: str, element) -> None:
        """Processa campo Título"""
        document['title'] = value
        
        # Extrair link se presente
        link = element.find('a')
        if link and link.get('href'):
            document['url'] = urljoin(self.base_url, link.get('href'))
        
        # Extrair descrição adicional
        full_text = element.get_text(strip=True)
        if len(full_text) > len(value):
            document['document_description'] = full_text
    
    def _process_data(self, document: Dict, value: str) -> None:
        """Processa campo Data"""
        try:
            if re.match(r'\\d{2}/\\d{2}/\\d{4}', value):
                day, month, year = value.split('/')
                document['enacting_date'] = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
            else:
                document['enacting_date'] = value
        except:
            document['enacting_date'] = value
    
    def _process_ementa(self, document: Dict, value: str) -> None:
        """Processa campo Ementa"""
        document['document_summary'] = value
    
    def _process_urn(self, document: Dict, value: str) -> None:
        """Processa campo URN"""
        document['urn'] = value
        
        # Classificar tipo baseado na URN
        if 'medida.provisoria' in value or 'mpv' in value:
            document['urn_type'] = 'legislation'
            document['document_type_full'] = 'Medida Provisória'
        elif ':lei:' in value:
            document['urn_type'] = 'legislation'
            document['document_type_full'] = 'Lei'
        elif ':decreto:' in value:
            document['urn_type'] = 'legislation'
            document['document_type_full'] = 'Decreto'
        elif ':portaria:' in value:
            document['urn_type'] = 'legislation'
            document['document_type_full'] = 'Portaria'
        elif ':resolucao:' in value:
            document['urn_type'] = 'legislation'
            document['document_type_full'] = 'Resolução'
        elif ':acordao:' in value or ':decisao:' in value:
            document['urn_type'] = 'jurisprudence'
            document['document_type_full'] = 'Acórdão'
        else:
            document['urn_type'] = 'other'
    
    def _process_tipo(self, document: Dict, value: str) -> None:
        """Processa campo Tipo (para doutrina)"""
        document['document_type_full'] = value
        document['urn_type'] = 'doutrina'
    
    def _process_autor(self, document: Dict, value: str) -> None:
        """Processa campo Autor"""
        document['justice'] = value
    
    def _process_assuntos(self, document: Dict, value: str) -> None:
        """Processa campo Assuntos"""
        if not document['document_summary']:
            document['document_summary'] = f"Assuntos: {value}"
        else:
            document['document_summary'] += f" | Assuntos: {value}"
    
    def _process_classificacao(self, document: Dict, value: str) -> None:
        """Processa campo Classificação"""
        if not document['document_description']:
            document['document_description'] = f"Classificação: {value}"
        else:
            document['document_description'] += f" | Classificação: {value}"
    
    def _finalize_document(self, document: Dict) -> Dict:
        """Finaliza processamento do documento"""
        # Evitar duplicatas por URN
        if document['urn'] and document['urn'] in self.processed_urns:
            return None
            
        if document['urn']:
            self.processed_urns.add(document['urn'])
        
        # Construir URL se não existir
        if not document['url'] and document['urn']:
            document['url'] = f"{self.base_url}/urn/{document['urn']}"
        
        # Garantir que campos obrigatórios não estejam vazios
        if not document['title']:
            document['title'] = f"Documento {document.get('result_number', 'N/A')}"
        
        return document
    
    def _has_next_page(self, search_term: str, current_page: int) -> bool:
        """Verifica se há próxima página disponível"""
        try:
            # Tentar acessar próxima página
            params = {
                'keyword': search_term,
                'f1-tipoDocumento': '',
                'startDoc': current_page * 20 + 1
            }
            
            response = self.session.get(self.search_url, params=params, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Verificar se há resultados
            results_text = soup.get_text()
            if "nenhum resultado encontrado" in results_text.lower():
                return False
            
            # Procurar por pelo menos um resultado numerado
            tables = soup.find_all('table')
            for table in tables:
                cells = table.find_all('td')
                for cell in cells:
                    text = cell.get_text(strip=True)
                    if text.isdigit() and 1 <= int(text) <= 20:
                        return True
                        
            return False
            
        except:
            return False
    
    def save_to_csv(self, documents: List[Dict], filename: str) -> None:
        """Salva documentos em arquivo CSV"""
        if not documents:
            logger.warning("Nenhum documento para salvar")
            return
            
        # Filtrar documentos None
        documents = [doc for doc in documents if doc is not None]
        
        fieldnames = [
            'search_term', 'date_searched', 'url', 'title', 'urn', 'urn_type',
            'country', 'state', 'municipality', 'justice', 'region', 'court_class',
            'document_type_full', 'enacting_date', 'document_description', 'document_summary'
        ]
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for doc in documents:
                    row = {field: doc.get(field, '') for field in fieldnames}
                    writer.writerow(row)
                    
            logger.info(f"Dados salvos em {filename}: {len(documents)} documentos")
            
        except Exception as e:
            logger.error(f"Erro ao salvar CSV: {str(e)}")
    
    def print_statistics(self) -> None:
        """Imprime estatísticas da execução"""
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']
            
            print("\\n" + "="*50)
            print("ESTATÍSTICAS DA EXECUÇÃO")
            print("="*50)
            print(f"Tempo total: {duration}")
            print(f"Páginas processadas: {self.stats['pages_processed']}")
            print(f"Total de documentos: {self.stats['total_documents']}")
            print(f"Extrações bem-sucedidas: {self.stats['successful_extractions']}")
            print(f"Extrações falharam: {self.stats['failed_extractions']}")
            
            if duration.total_seconds() > 0:
                rate = self.stats['total_documents'] / duration.total_seconds() * 60
                print(f"Taxa de extração: {rate:.1f} documentos/minuto")
            
            print("="*50)

def search_multiple_terms(terms: List[str], max_results_per_term: Optional[int] = None) -> None:
    """
    Busca múltiplos termos e salva em arquivo consolidado
    """
    scraper = LexMLScraperFinalCorrigido()
    all_documents = []
    
    for i, term in enumerate(terms, 1):
        print(f"\\n[{i}/{len(terms)}] Processando termo: '{term}'")
        
        try:
            documents = scraper.search_documents(term, max_results_per_term)
            all_documents.extend(documents)
            
            print(f"Termo '{term}': {len(documents)} documentos extraídos")
            
            # Salvar progresso parcial
            if documents:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                partial_filename = f"lexml_partial_{term.replace(' ', '_')}_{timestamp}.csv"
                scraper.save_to_csv(documents, partial_filename)
            
        except Exception as e:
            logger.error(f"Erro ao processar termo '{term}': {str(e)}")
            continue
        
        # Pausa entre termos
        if i < len(terms):
            time.sleep(3)
    
    # Salvar arquivo consolidado
    if all_documents:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        consolidated_filename = f"lexml_consolidated_{timestamp}.csv"
        scraper.save_to_csv(all_documents, consolidated_filename)
        
        print(f"\\nARQUIVO CONSOLIDADO: {consolidated_filename}")
        print(f"TOTAL DE DOCUMENTOS: {len(all_documents)}")
    
    # Mostrar estatísticas finais
    scraper.print_statistics()

def main():
    """Função principal para teste"""
    scraper = LexMLScraperFinalCorrigido()
    
    # Teste com termo específico
    search_term = "transporte de carga"
    max_results = 50  # Limite para teste
    
    print(f"Iniciando busca por: '{search_term}'")
    print(f"Limite: {max_results} documentos")
    
    # Executar busca
    documents = scraper.search_documents(search_term, max_results)
    
    # Salvar resultados
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"lexml_final_test_{timestamp}.csv"
    scraper.save_to_csv(documents, filename)
    
    # Mostrar estatísticas
    scraper.print_statistics()
    
    # Mostrar amostra dos resultados
    if documents:
        print("\\nAMOSTRA DOS RESULTADOS:")
        print("-" * 50)
        for i, doc in enumerate(documents[:5]):
            print(f"Documento {i+1}:")
            print(f"  Título: {doc['title']}")
            print(f"  Tipo: {doc['document_type_full']}")
            print(f"  Data: {doc['enacting_date']}")
            print(f"  URN: {doc['urn']}")
            print()

if __name__ == "__main__":
    main()

