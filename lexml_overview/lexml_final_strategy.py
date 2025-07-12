#!/usr/bin/env python3
"""
Estratégia Final para LexML - Baseada em Análise Real
Autor: Manus AI
Data: 2025-07-12

Esta estratégia é baseada na análise real da estrutura HTML do LexML
e implementa tanto web scraping quanto possível uso de API.
"""

import requests
import pandas as pd
from bs4 import BeautifulSoup
import time
import re
from datetime import datetime
from typing import Dict, List, Optional, Union
import logging
import json
from urllib.parse import urljoin, urlparse, parse_qs

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LexMLFinalStrategy:
    """
    Estratégia final para extração de dados do LexML.
    Combina web scraping com análise de estrutura real.
    """
    
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br"
        self.search_url = f"{self.base_url}/busca/search"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        })
    
    def search_documents(self, 
                        search_term: str,
                        document_category: str = "",
                        authority_sphere: str = "",
                        max_results: int = 100) -> List[Dict]:
        """
        Busca documentos no LexML usando a estratégia otimizada.
        
        Args:
            search_term: Termo de busca
            document_category: Categoria do documento (Legislação, Jurisprudência, etc.)
            authority_sphere: Esfera da autoridade (Federal, Estadual, etc.)
            max_results: Número máximo de resultados
            
        Returns:
            Lista de documentos encontrados
        """
        logger.info(f"Iniciando busca por: '{search_term}'")
        
        # Parâmetros de busca
        params = {
            'keyword': search_term,
            'f1-tipoDocumento': document_category
        }
        
        if authority_sphere:
            params['f2-autoridade'] = authority_sphere
        
        try:
            # Faz a requisição inicial
            response = self.session.get(self.search_url, params=params)
            response.raise_for_status()
            
            logger.info(f"URL da busca: {response.url}")
            
            # Extrai resultados da primeira página
            results = self._extract_results_from_response(response.text, search_term)
            
            # Se há mais páginas e não atingiu o limite, continua
            page = 2
            while len(results) < max_results:
                next_url = self._get_next_page_url(response.text, response.url)
                if not next_url:
                    break
                
                logger.info(f"Buscando página {page}")
                response = self.session.get(next_url)
                response.raise_for_status()
                
                page_results = self._extract_results_from_response(response.text, search_term)
                if not page_results:
                    break
                
                results.extend(page_results)
                page += 1
                time.sleep(1)  # Rate limiting
                
                if len(results) >= max_results:
                    results = results[:max_results]
                    break
            
            logger.info(f"Total de resultados extraídos: {len(results)}")
            return results
            
        except Exception as e:
            logger.error(f"Erro na busca: {e}")
            return []
    
    def _extract_results_from_response(self, html_content: str, search_term: str) -> List[Dict]:
        """
        Extrai resultados da resposta HTML.
        Usa múltiplas estratégias baseadas na estrutura real do LexML.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        results = []
        
        # Estratégia 1: Busca por padrões de resultado conhecidos
        # Baseado na análise da estrutura real do LexML
        
        # Procura por elementos que contêm "Adicionar" (botão de adicionar à cesta)
        add_buttons = soup.find_all('a', string='Adicionar')
        logger.info(f"Encontrados {len(add_buttons)} botões 'Adicionar'")
        
        for button in add_buttons:
            try:
                # Navega para o container do resultado
                result_container = button.find_parent('table') or button.find_parent('div', class_='resultado')
                if result_container:
                    result = self._extract_single_result_from_container(result_container, search_term)
                    if result:
                        results.append(result)
            except Exception as e:
                logger.warning(f"Erro ao extrair resultado: {e}")
                continue
        
        # Estratégia 2: Busca por padrões de texto específicos
        if not results:
            results = self._extract_by_text_patterns(soup, search_term)
        
        # Estratégia 3: Busca por estrutura de tabela genérica
        if not results:
            results = self._extract_from_generic_tables(soup, search_term)
        
        return results
    
    def _extract_single_result_from_container(self, container, search_term: str) -> Optional[Dict]:
        """
        Extrai um único resultado de um container HTML.
        """
        try:
            result = {
                'search_term': search_term,
                'date_searched': datetime.now().isoformat(),
                'url': '',
                'title': '',
                'urn': '',
                'urn_type': '',
                'country': '',
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
            
            # Extrai texto completo do container
            full_text = container.get_text()
            
            # Busca por padrões específicos no texto
            patterns = {
                'localidade': r'Localidade\s*:?\s*([^\n\r]+)',
                'autoridade': r'Autoridade\s*:?\s*([^\n\r]+)',
                'titulo': r'Título\s*:?\s*([^\n\r]+)',
                'data': r'Data\s*:?\s*([^\n\r]+)',
                'ementa': r'Ementa\s*:?\s*([^\n\r]+)',
                'urn': r'URN\s*:?\s*(urn:lex:[^\s\n\r]+)',
                'assuntos': r'Assuntos\s*:?\s*([^\n\r]+)'
            }
            
            for field, pattern in patterns.items():
                match = re.search(pattern, full_text, re.IGNORECASE | re.MULTILINE)
                if match:
                    value = match.group(1).strip()
                    
                    if field == 'titulo':
                        result['title'] = value
                    elif field == 'data':
                        result['enacting_date'] = value
                    elif field == 'ementa':
                        result['document_summary'] = value
                    elif field == 'urn':
                        result['urn'] = value
                        # Faz parsing da URN
                        urn_data = self.parse_urn(value)
                        result.update(urn_data)
                    elif field == 'assuntos':
                        result['document_description'] = value
            
            # Busca por links
            links = container.find_all('a', href=True)
            for link in links:
                href = link.get('href')
                if href and not href.startswith('#') and 'Adicionar' not in link.get_text():
                    result['url'] = urljoin(self.base_url, href)
                    if not result['title']:
                        result['title'] = link.get_text(strip=True)
                    break
            
            # Verifica se extraiu dados suficientes
            if result['title'] or result['urn'] or result['url']:
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao extrair resultado do container: {e}")
            return None
    
    def _extract_by_text_patterns(self, soup, search_term: str) -> List[Dict]:
        """
        Extrai resultados usando padrões de texto.
        """
        results = []
        
        # Procura por todas as URNs na página
        urn_pattern = r'urn:lex:[^\s\n\r]+'
        page_text = soup.get_text()
        urns = re.findall(urn_pattern, page_text, re.IGNORECASE)
        
        logger.info(f"Encontradas {len(urns)} URNs na página")
        
        for urn in urns:
            try:
                # Encontra o contexto ao redor da URN
                urn_element = soup.find(text=re.compile(re.escape(urn), re.IGNORECASE))
                if urn_element:
                    # Navega para o container pai
                    container = urn_element.parent
                    while container and container.name not in ['table', 'div', 'section', 'article']:
                        container = container.parent
                    
                    if container:
                        result = self._extract_single_result_from_container(container, search_term)
                        if result and result not in results:
                            results.append(result)
                            
            except Exception as e:
                logger.warning(f"Erro ao processar URN {urn}: {e}")
                continue
        
        return results
    
    def _extract_from_generic_tables(self, soup, search_term: str) -> List[Dict]:
        """
        Extrai resultados de tabelas genéricas.
        """
        results = []
        
        # Procura por todas as tabelas
        tables = soup.find_all('table')
        
        for table in tables:
            try:
                table_text = table.get_text()
                
                # Verifica se a tabela contém dados relevantes
                if any(keyword in table_text.lower() for keyword in ['localidade', 'autoridade', 'título', 'urn']):
                    result = self._extract_single_result_from_container(table, search_term)
                    if result:
                        results.append(result)
                        
            except Exception as e:
                logger.warning(f"Erro ao processar tabela: {e}")
                continue
        
        return results
    
    def _get_next_page_url(self, html_content: str, current_url: str) -> Optional[str]:
        """
        Encontra a URL da próxima página.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Procura por link "Próxima"
        next_links = soup.find_all('a', string=re.compile(r'Próxima|Next', re.IGNORECASE))
        
        for link in next_links:
            href = link.get('href')
            if href:
                return urljoin(current_url, href)
        
        # Procura por links de página numerados
        page_links = soup.find_all('a', href=re.compile(r'page=\d+'))
        if page_links:
            # Pega o último link de página
            last_link = page_links[-1]
            href = last_link.get('href')
            if href:
                return urljoin(current_url, href)
        
        return None
    
    def parse_urn(self, urn: str) -> Dict[str, str]:
        """
        Faz parsing de uma URN do LexML.
        
        Args:
            urn: URN no formato LexML
            
        Returns:
            Dicionário com componentes da URN
        """
        if not urn or not urn.startswith('urn:lex:'):
            return {}
        
        try:
            # Remove prefixo urn:lex:
            urn_content = urn[8:]
            
            result = {
                'urn_type': 'unknown',
                'country': '',
                'state': '',
                'municipality': '',
                'justice': '',
                'region': '',
                'court_class': '',
                'document_type_full': '',
                'enacting_date': ''
            }
            
            # Divide por ':' para separar as partes principais
            main_parts = urn_content.split(':')
            
            if len(main_parts) >= 1:
                # Primeira parte: localização/jurisdição
                location_part = main_parts[0]
                
                # Analisa se é legislação, jurisprudência ou doutrina
                if 'justica' in location_part:
                    result['urn_type'] = 'jurisprudence'
                    result = self._parse_jurisprudence_urn(main_parts, result)
                elif any(level in location_part for level in ['federal', 'estadual', 'municipal', 'distrital']):
                    result['urn_type'] = 'legislation'
                    result = self._parse_legislation_urn(main_parts, result)
                else:
                    result['urn_type'] = 'doctrine'
                    result = self._parse_doctrine_urn(main_parts, result)
                
                # Extrai país
                if location_part.startswith('br'):
                    result['country'] = 'br'
            
            return result
            
        except Exception as e:
            logger.error(f"Erro no parsing da URN {urn}: {e}")
            return {}
    
    def _parse_legislation_urn(self, parts: List[str], result: Dict[str, str]) -> Dict[str, str]:
        """Parse URN de legislação."""
        try:
            # Exemplo: br:federal:lei:2018-05-27;832
            if len(parts) >= 1:
                location_parts = parts[0].split(';')[0].split('.')
                
                if len(location_parts) >= 2:
                    if location_parts[1] in ['federal', 'estadual', 'municipal', 'distrital']:
                        result['authority_level'] = location_parts[1]
                    else:
                        # Pode ser estado.município
                        if len(location_parts) >= 3:
                            result['state'] = location_parts[1].replace('-', ' ').title()
                            result['municipality'] = location_parts[2].replace('-', ' ').title()
            
            if len(parts) >= 2:
                result['document_type_full'] = parts[1]
            
            if len(parts) >= 3:
                date_number = parts[2].split(';')
                if len(date_number) >= 1:
                    result['enacting_date'] = date_number[0]
                if len(date_number) >= 2:
                    result['document_number'] = date_number[1]
            
            return result
            
        except Exception:
            return result
    
    def _parse_jurisprudence_urn(self, parts: List[str], result: Dict[str, str]) -> Dict[str, str]:
        """Parse URN de jurisprudência."""
        try:
            # Exemplo: br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.6:acordao:2015-11-19;00008058020145010301
            if len(parts) >= 1:
                location_parts = parts[0].split(';')
                
                for part in location_parts:
                    if 'justica' in part:
                        justice_parts = part.split('.')
                        if len(justice_parts) >= 2:
                            result['justice'] = f"Justiça {justice_parts[1].title()}"
                    elif 'regiao' in part:
                        result['region'] = part.replace('.', ' ').title()
            
            if len(parts) >= 2:
                court_parts = parts[1].split(';')
                if court_parts:
                    result['court_class'] = court_parts[0].replace('.', ' ').title()
            
            if len(parts) >= 3:
                result['document_type_full'] = parts[2]
            
            if len(parts) >= 4:
                date_number = parts[3].split(';')
                if len(date_number) >= 1:
                    result['enacting_date'] = date_number[0]
                if len(date_number) >= 2:
                    result['document_number'] = date_number[1]
            
            return result
            
        except Exception:
            return result
    
    def _parse_doctrine_urn(self, parts: List[str], result: Dict[str, str]) -> Dict[str, str]:
        """Parse URN de doutrina."""
        try:
            result['document_type_full'] = 'doutrina'
            
            if len(parts) >= 2:
                result['source_type'] = parts[1]
            
            return result
            
        except Exception:
            return result
    
    def search_multiple_terms(self, terms: List[str], **kwargs) -> pd.DataFrame:
        """
        Busca múltiplos termos e retorna DataFrame consolidado.
        
        Args:
            terms: Lista de termos de busca
            **kwargs: Argumentos adicionais para search_documents
            
        Returns:
            DataFrame com todos os resultados
        """
        all_results = []
        
        for term in terms:
            logger.info(f"Buscando termo: {term}")
            results = self.search_documents(term, **kwargs)
            all_results.extend(results)
            time.sleep(2)  # Rate limiting entre termos
        
        # Converte para DataFrame
        df = pd.DataFrame(all_results)
        
        # Remove duplicatas baseado na URN
        if 'urn' in df.columns:
            df = df.drop_duplicates(subset=['urn'], keep='first')
        
        return df

def load_search_terms(file_path: str) -> List[str]:
    """
    Carrega termos de busca de um arquivo.
    
    Args:
        file_path: Caminho para o arquivo
        
    Returns:
        Lista de termos
    """
    terms = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extrai termos entre aspas
        quoted_terms = re.findall(r'"([^"]+)"', content)
        terms.extend(quoted_terms)
        
        # Extrai termos de linhas que começam com palavra
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                # Remove aspas se houver
                term = line.strip('"\'')
                if term and term not in terms:
                    terms.append(term)
        
        # Remove duplicatas e termos vazios
        terms = [term.strip() for term in terms if term.strip()]
        terms = list(set(terms))
        
        logger.info(f"Carregados {len(terms)} termos únicos")
        return terms
        
    except Exception as e:
        logger.error(f"Erro ao carregar termos: {e}")
        return []

def main():
    """Função principal para demonstração."""
    strategy = LexMLFinalStrategy()
    
    # Teste com um termo
    results = strategy.search_documents("transporte de carga", max_results=10)
    
    if results:
        df = pd.DataFrame(results)
        print(f"Resultados encontrados: {len(df)}")
        print("\nColunas disponíveis:")
        print(df.columns.tolist())
        
        # Salva resultados
        df.to_csv('lexml_final_results.csv', index=False, encoding='utf-8')
        print("\nResultados salvos em: lexml_final_results.csv")
        
        # Mostra amostra
        print("\nAmostra dos resultados:")
        for col in ['title', 'urn', 'document_summary']:
            if col in df.columns:
                print(f"\n{col}:")
                print(df[col].head(3).tolist())
    else:
        print("Nenhum resultado encontrado")

if __name__ == "__main__":
    main()

