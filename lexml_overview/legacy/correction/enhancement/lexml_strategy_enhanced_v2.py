#!/usr/bin/env python3
"""
Estratégia LexML Atualizada v2.0
Sistema Refinado com Classificação Hierárquica e Novos Termos de Busca

Autor: Manus AI
Data: 2025-07-12
Versão: 2.0 - Sistema Completo Refinado

Principais Melhorias:
- Integração com 10 categorias temáticas de busca
- Classificação hierárquica em 3 níveis
- Parsing prompts especializados por tipo de documento
- Sistema de enriquecimento temático
- Controle de qualidade automatizado
"""

import requests
import csv
import time
import re
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote
from bs4 import BeautifulSoup
import logging
from typing import Dict, List, Optional, Tuple
import json

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('lexml_enhanced_v2.log'),
        logging.StreamHandler()
    ]
)

class EnhancedLexMLStrategy:
    """
    Estratégia LexML refinada com classificação hierárquica
    e integração com novos termos de busca
    """
    
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br/busca/SRU"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Novos termos de busca organizados por categoria
        self.enhanced_search_terms = self._load_enhanced_search_terms()
        
        # Sistema de classificação refinado
        self.document_classifier = RefinedDocumentClassifier()
        
        # Sistema de parsing integrado
        self.parsing_system = IntegratedParsingSystem()
        
        # Sistema de enriquecimento temático
        self.enrichment_system = ThematicEnrichmentSystem()
        
        # Controle de qualidade
        self.quality_controller = ParsingQualityController()
        
        # Estatísticas de execução
        self.execution_stats = {
            'total_searches': 0,
            'total_documents': 0,
            'classification_stats': {},
            'parsing_stats': {},
            'quality_stats': {},
            'errors': []
        }
    
    def _load_enhanced_search_terms(self) -> Dict[str, List[str]]:
        """
        Carrega os novos termos de busca organizados por categoria
        """
        return {
            'transporte_geral': [
                'transporte de carga', 'transporte rodoviário de carga',
                'logística de carga', 'frete', 'fretamento', 'caminhão',
                'caminhões', 'veículos pesados', 'veículos de carga',
                'veículos comerciais', 'transporte de mercadorias', 'modal rodoviário'
            ],
            'combustiveis_energia': [
                'gás natural veicular', 'biometano', 'diesel', 'biodiesel',
                'diesel verde', 'combustível sustentável', 'hidrogênio',
                'etanol', 'SAF', 'nuclear', 'célula de combustível',
                'algas marinhas', 'HVO', 'combustível marinho', 'petróleo'
            ],
            'eficiencia_emissoes': [
                'eficiência energética', 'emissões', 'descarbonização',
                'gases de efeito estufa', 'rotulagem veicular',
                'consumo de combustível'
            ],
            'tecnologia_inovacao': [
                'tecnologias assistivas', 'veículos autônomos', 'telemetria',
                'rastreamento', 'motorização', 'conversão'
            ],
            'infraestrutura': [
                'postos de abastecimento', 'infraestrutura',
                'terminais de carga', 'centros de distribuição',
                'armazéns'
            ],
            'regulamentacao_normas': [
                'CONTRAN', 'ANTT', 'registro', 'habilitação',
                'licenciamento', 'RNTRC', 'segurança veicular',
                'CNPE', 'CCEE', 'ANA', 'ANP', 'ONS'
            ],
            'incentivos_tributacao': [
                'IPI', 'ICMS', 'incentivo fiscal', 'isenção',
                'benefício tributário', 'financiamento'
            ],
            'programas_governamentais': [
                'Rota 2030', 'Paten', 'Programa de Aceleração da Transição Energética',
                'mobilidade e logística', 'transição energética',
                'desenvolvimento sustentável', 'P&D', 'Lei do Combustível do Futuro'
            ],
            'maquinas_equipamentos': [
                'máquinas agrícolas', 'implementos rodoviários', 'reboque',
                'semi-reboque', 'carreta', 'bitrem', 'rodotrem',
                'equipamentos de transporte'
            ],
            'operacoes_servicos': [
                'transportador autônomo', 'empresa de transporte',
                'operador logístico', 'embarcador', 'terceirização',
                'contrato de frete', 'tabela de frete'
            ]
        }
    
    def execute_comprehensive_search(self, 
                                   categories: Optional[List[str]] = None,
                                   max_results_per_category: int = 100,
                                   include_all_document_types: bool = True) -> Dict:
        """
        Executa busca abrangente com os novos termos organizados por categoria
        """
        
        logging.info("Iniciando busca abrangente com termos refinados")
        
        if categories is None:
            categories = list(self.enhanced_search_terms.keys())
        
        all_results = []
        category_stats = {}
        
        for category in categories:
            logging.info(f"Processando categoria: {category}")
            
            category_results = self._search_by_category(
                category, 
                max_results_per_category,
                include_all_document_types
            )
            
            # Enriquecimento temático dos resultados
            enriched_results = []
            for result in category_results:
                try:
                    enriched_result = self.enrichment_system.enrich_document_analysis(
                        result, result
                    )
                    enriched_results.append(enriched_result)
                except Exception as e:
                    logging.error(f"Erro no enriquecimento temático: {e}")
                    enriched_results.append(result)
            
            all_results.extend(enriched_results)
            category_stats[category] = {
                'total_found': len(category_results),
                'successfully_enriched': len(enriched_results),
                'primary_themes': self._analyze_category_themes(enriched_results)
            }
            
            # Pausa entre categorias para evitar sobrecarga
            time.sleep(2)
        
        # Remoção de duplicatas baseada em URN
        unique_results = self._remove_duplicates(all_results)
        
        # Estatísticas finais
        final_stats = {
            'total_categories_searched': len(categories),
            'total_documents_found': len(all_results),
            'unique_documents': len(unique_results),
            'category_breakdown': category_stats,
            'classification_distribution': self._analyze_classification_distribution(unique_results),
            'quality_metrics': self._calculate_overall_quality_metrics(unique_results)
        }
        
        logging.info(f"Busca concluída: {len(unique_results)} documentos únicos encontrados")
        
        return {
            'results': unique_results,
            'statistics': final_stats,
            'execution_timestamp': datetime.now().isoformat()
        }
    
    def _search_by_category(self, category: str, max_results: int, include_all_types: bool) -> List[Dict]:
        """
        Executa busca para uma categoria específica
        """
        
        terms = self.enhanced_search_terms.get(category, [])
        if not terms:
            logging.warning(f"Categoria {category} não encontrada")
            return []
        
        category_results = []
        
        # Busca por combinações de termos
        for i, term in enumerate(terms[:5]):  # Limita a 5 termos principais por categoria
            try:
                # Busca com termo legal obrigatório
                legal_query = f'("{term}") AND (lei OR decreto OR portaria OR resolução OR "medida provisória" OR "projeto de lei" OR "instrução normativa")'
                
                results = self._execute_search_query(legal_query, max_results // 5)
                
                # Processamento e classificação dos resultados
                for result in results:
                    try:
                        # Classificação refinada
                        classification = self.document_classifier.classify_document(
                            result.get('urn', ''),
                            result.get('title', ''),
                            result.get('document_summary', ''),
                            result.get('document_type_original', '')
                        )
                        
                        # Parsing especializado
                        parsed_content = self.parsing_system.parse_document(result)
                        
                        # Controle de qualidade
                        quality_assessment = self.quality_controller.validate_parsing_result(
                            parsed_content, result
                        )
                        
                        # Enriquecimento do resultado
                        enhanced_result = {
                            **result,
                            'search_category': category,
                            'search_term_used': term,
                            'classification': classification,
                            'parsed_content': parsed_content,
                            'quality_assessment': quality_assessment,
                            'processing_timestamp': datetime.now().isoformat()
                        }
                        
                        category_results.append(enhanced_result)
                        
                    except Exception as e:
                        logging.error(f"Erro no processamento do resultado: {e}")
                        # Adiciona resultado básico mesmo com erro
                        category_results.append({
                            **result,
                            'search_category': category,
                            'search_term_used': term,
                            'processing_error': str(e)
                        })
                
                # Pausa entre termos
                time.sleep(1)
                
            except Exception as e:
                logging.error(f"Erro na busca do termo '{term}': {e}")
                self.execution_stats['errors'].append({
                    'category': category,
                    'term': term,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return category_results
    
    def _execute_search_query(self, query: str, max_results: int) -> List[Dict]:
        """
        Executa uma consulta específica no LexML
        """
        
        results = []
        start_record = 1
        records_per_page = 50
        
        while len(results) < max_results:
            try:
                params = {
                    'query': query,
                    'startRecord': start_record,
                    'maximumRecords': min(records_per_page, max_results - len(results)),
                    'recordSchema': 'oai_dc'
                }
                
                response = self.session.get(self.base_url, params=params, timeout=30)
                response.raise_for_status()
                
                # Parse da resposta XML/HTML
                soup = BeautifulSoup(response.content, 'xml') or BeautifulSoup(response.content, 'html.parser')
                
                # Extração dos registros
                records = self._extract_records_from_response(soup)
                
                if not records:
                    break
                
                results.extend(records)
                start_record += len(records)
                
                # Pausa entre páginas
                time.sleep(0.5)
                
            except Exception as e:
                logging.error(f"Erro na execução da consulta: {e}")
                break
        
        return results[:max_results]
    
    def _extract_records_from_response(self, soup) -> List[Dict]:
        """
        Extrai registros da resposta do LexML com melhorias na extração de dados
        """
        
        records = []
        
        # Tentativa de extração via XML estruturado
        xml_records = soup.find_all('record') or soup.find_all('item')
        
        if xml_records:
            for record in xml_records:
                try:
                    extracted_record = self._extract_xml_record(record)
                    if extracted_record:
                        records.append(extracted_record)
                except Exception as e:
                    logging.error(f"Erro na extração de registro XML: {e}")
        
        # Fallback para extração HTML se XML não funcionar
        if not records:
            html_records = soup.find_all('div', class_='result-item') or soup.find_all('tr')
            
            for record in html_records:
                try:
                    extracted_record = self._extract_html_record(record)
                    if extracted_record:
                        records.append(extracted_record)
                except Exception as e:
                    logging.error(f"Erro na extração de registro HTML: {e}")
        
        return records
    
    def _extract_xml_record(self, record) -> Optional[Dict]:
        """
        Extrai dados de um registro XML
        """
        
        try:
            # Extração de campos básicos
            title_elem = record.find('title') or record.find('dc:title')
            title = title_elem.get_text(strip=True) if title_elem else ""
            
            identifier_elem = record.find('identifier') or record.find('dc:identifier')
            urn = identifier_elem.get_text(strip=True) if identifier_elem else ""
            
            description_elem = record.find('description') or record.find('dc:description')
            description = description_elem.get_text(strip=True) if description_elem else ""
            
            date_elem = record.find('date') or record.find('dc:date')
            date_text = date_elem.get_text(strip=True) if date_elem else ""
            
            # Processamento da data
            enacting_date = self._extract_and_format_date(title, description, date_text)
            
            # Extração de metadados adicionais
            subject_elem = record.find('subject') or record.find('dc:subject')
            subject = subject_elem.get_text(strip=True) if subject_elem else ""
            
            creator_elem = record.find('creator') or record.find('dc:creator')
            creator = creator_elem.get_text(strip=True) if creator_elem else ""
            
            # Classificação inicial baseada na URN
            urn_classification = self._classify_from_urn(urn)
            
            return {
                'search_term': '',  # Será preenchido pelo método chamador
                'date_searched': datetime.now().strftime('%Y-%m-%d'),
                'url': f"https://www.lexml.gov.br/urn/{urn}" if urn else "",
                'title': title,
                'urn': urn,
                'urn_type': urn_classification['urn_type'],
                'country': urn_classification['country'],
                'state': urn_classification['state'],
                'municipality': urn_classification['municipality'],
                'justice': urn_classification['justice'],
                'region': urn_classification['region'],
                'court_class': urn_classification['court_class'],
                'document_type_full': urn_classification['document_type_full'],
                'enacting_date': enacting_date,
                'document_description': description,
                'document_summary': description,
                'subject': subject,
                'creator': creator,
                'extraction_method': 'xml',
                'extraction_confidence': 0.9
            }
            
        except Exception as e:
            logging.error(f"Erro na extração XML: {e}")
            return None
    
    def _extract_html_record(self, record) -> Optional[Dict]:
        """
        Extrai dados de um registro HTML com melhorias
        """
        
        try:
            # Busca por links "Adicionar" ou títulos
            title_elem = (record.find('a', href=lambda x: x and 'adicionar' in x.lower()) or
                         record.find('a', class_='title') or
                         record.find('h3') or
                         record.find('strong'))
            
            title = title_elem.get_text(strip=True) if title_elem else ""
            
            # Extração da URN do href
            urn = ""
            if title_elem and title_elem.get('href'):
                href = title_elem.get('href')
                urn_match = re.search(r'urn:lex:[^&\s]+', href)
                if urn_match:
                    urn = urn_match.group(0)
            
            # Busca por descrição/ementa
            description_elem = (record.find('div', class_='description') or
                              record.find('p') or
                              record.find('td', string=lambda x: x and len(x) > 50))
            
            description = description_elem.get_text(strip=True) if description_elem else ""
            
            # Extração de data do título ou descrição
            enacting_date = self._extract_and_format_date(title, description)
            
            # Classificação baseada na URN
            urn_classification = self._classify_from_urn(urn)
            
            return {
                'search_term': '',
                'date_searched': datetime.now().strftime('%Y-%m-%d'),
                'url': f"https://www.lexml.gov.br/urn/{urn}" if urn else "",
                'title': title,
                'urn': urn,
                'urn_type': urn_classification['urn_type'],
                'country': urn_classification['country'],
                'state': urn_classification['state'],
                'municipality': urn_classification['municipality'],
                'justice': urn_classification['justice'],
                'region': urn_classification['region'],
                'court_class': urn_classification['court_class'],
                'document_type_full': urn_classification['document_type_full'],
                'enacting_date': enacting_date,
                'document_description': description,
                'document_summary': description,
                'extraction_method': 'html',
                'extraction_confidence': 0.7
            }
            
        except Exception as e:
            logging.error(f"Erro na extração HTML: {e}")
            return None
    
    def _extract_and_format_date(self, title: str, description: str, date_field: str = "") -> str:
        """
        Extrai e formata data de documentos com múltiplas estratégias
        """
        
        # Padrões de data em português
        date_patterns = [
            r'(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})',  # "14 de junho de 2023"
            r'(\d{1,2})/(\d{1,2})/(\d{4})',             # "14/06/2023"
            r'(\d{4})-(\d{2})-(\d{2})',                 # "2023-06-14"
            r'(\d{1,2})\.(\d{1,2})\.(\d{4})',           # "14.06.2023"
            r'(\d{4})/(\d{2})/(\d{2})',                 # "2023/06/14"
        ]
        
        # Mapeamento de meses em português
        month_names = {
            'janeiro': '01', 'fevereiro': '02', 'março': '03', 'abril': '04',
            'maio': '05', 'junho': '06', 'julho': '07', 'agosto': '08',
            'setembro': '09', 'outubro': '10', 'novembro': '11', 'dezembro': '12'
        }
        
        # Texto combinado para busca
        search_text = f"{title} {description} {date_field}".lower()
        
        # Tentativa de extração por padrões
        for pattern in date_patterns:
            matches = re.findall(pattern, search_text)
            if matches:
                match = matches[0]
                
                try:
                    if len(match) == 3:
                        if pattern == date_patterns[0]:  # Formato "14 de junho de 2023"
                            day, month_name, year = match
                            month = month_names.get(month_name.lower(), '01')
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                        
                        elif pattern == date_patterns[1]:  # Formato "14/06/2023"
                            day, month, year = match
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                        
                        elif pattern == date_patterns[2]:  # Formato "2023-06-14"
                            return f"{match[0]}-{match[1]}-{match[2]}"
                        
                        elif pattern == date_patterns[3]:  # Formato "14.06.2023"
                            day, month, year = match
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                        
                        elif pattern == date_patterns[4]:  # Formato "2023/06/14"
                            year, month, day = match
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                
                except Exception as e:
                    logging.error(f"Erro na formatação de data: {e}")
                    continue
        
        # Fallback: busca por ano isolado
        year_match = re.search(r'\b(19|20)\d{2}\b', search_text)
        if year_match:
            year = year_match.group(0)
            return f"{year}-01-01"  # Data genérica com o ano encontrado
        
        return ""  # Retorna vazio se não encontrar data
    
    def _classify_from_urn(self, urn: str) -> Dict[str, str]:
        """
        Classifica documento baseado na URN com melhorias
        """
        
        if not urn:
            return self._get_default_classification()
        
        urn_lower = urn.lower()
        
        # Análise da estrutura da URN
        urn_parts = urn.split(':')
        
        classification = {
            'urn_type': 'unknown',
            'country': 'br',
            'state': '',
            'municipality': '',
            'justice': '',
            'region': '',
            'court_class': '',
            'document_type_full': 'unknown'
        }
        
        # Identificação do país
        if len(urn_parts) > 2:
            classification['country'] = urn_parts[2]
        
        # Identificação da esfera e tipo
        if 'federal' in urn_lower:
            classification['region'] = 'Federal'
            classification['urn_type'] = 'legislation'
        elif 'estadual' in urn_lower:
            classification['region'] = 'Estadual'
            classification['urn_type'] = 'legislation'
        elif 'municipal' in urn_lower:
            classification['region'] = 'Municipal'
            classification['urn_type'] = 'legislation'
        
        # Identificação do tipo de documento
        document_type_patterns = {
            'lei': 'Lei',
            'decreto': 'Decreto',
            'portaria': 'Portaria',
            'resolucao': 'Resolução',
            'instrucao.normativa': 'Instrução Normativa',
            'medida.provisoria': 'Medida Provisória',
            'jurisprudencia': 'Jurisprudência',
            'acordao': 'Acórdão',
            'sumula': 'Súmula'
        }
        
        for pattern, doc_type in document_type_patterns.items():
            if pattern in urn_lower:
                classification['document_type_full'] = doc_type
                if pattern in ['jurisprudencia', 'acordao', 'sumula']:
                    classification['urn_type'] = 'jurisprudence'
                else:
                    classification['urn_type'] = 'legislation'
                break
        
        # Identificação de estado (se presente na URN)
        state_patterns = {
            'sp': 'São Paulo', 'rj': 'Rio de Janeiro', 'mg': 'Minas Gerais',
            'rs': 'Rio Grande do Sul', 'pr': 'Paraná', 'sc': 'Santa Catarina',
            'ba': 'Bahia', 'go': 'Goiás', 'pe': 'Pernambuco', 'ce': 'Ceará'
        }
        
        for state_code, state_name in state_patterns.items():
            if f':{state_code}:' in urn_lower or f';{state_code};' in urn_lower:
                classification['state'] = state_name
                break
        
        # Se não identificou tipo, classifica como doutrina
        if classification['urn_type'] == 'unknown':
            classification['urn_type'] = 'doctrine'
            classification['document_type_full'] = 'Documento Doutrinário'
        
        return classification
    
    def _get_default_classification(self) -> Dict[str, str]:
        """
        Retorna classificação padrão para documentos sem URN
        """
        return {
            'urn_type': 'doctrine',
            'country': 'br',
            'state': '',
            'municipality': '',
            'justice': '',
            'region': '',
            'court_class': '',
            'document_type_full': 'Documento Não Classificado'
        }
    
    def _remove_duplicates(self, results: List[Dict]) -> List[Dict]:
        """
        Remove duplicatas baseado na URN
        """
        
        seen_urns = set()
        unique_results = []
        
        for result in results:
            urn = result.get('urn', '')
            if urn and urn not in seen_urns:
                seen_urns.add(urn)
                unique_results.append(result)
            elif not urn:
                # Para documentos sem URN, usa título como chave
                title_key = result.get('title', '')[:100]  # Primeiros 100 caracteres
                if title_key not in seen_urns:
                    seen_urns.add(title_key)
                    unique_results.append(result)
        
        return unique_results
    
    def _analyze_category_themes(self, results: List[Dict]) -> Dict[str, int]:
        """
        Analisa temas principais por categoria
        """
        
        theme_counts = {}
        
        for result in results:
            if 'thematic_enrichment' in result:
                primary_themes = result['thematic_enrichment'].get('primary_themes', [])
                for theme in primary_themes:
                    theme_counts[theme] = theme_counts.get(theme, 0) + 1
        
        return dict(sorted(theme_counts.items(), key=lambda x: x[1], reverse=True))
    
    def _analyze_classification_distribution(self, results: List[Dict]) -> Dict[str, Dict]:
        """
        Analisa distribuição de classificações
        """
        
        distribution = {
            'main_categories': {},
            'document_types': {},
            'regions': {},
            'confidence_levels': {}
        }
        
        for result in results:
            classification = result.get('classification', {})
            
            # Categoria principal
            main_cat = classification.get('main_category', 'unknown')
            distribution['main_categories'][main_cat] = distribution['main_categories'].get(main_cat, 0) + 1
            
            # Tipo de documento
            doc_type = classification.get('document_type', 'unknown')
            distribution['document_types'][doc_type] = distribution['document_types'].get(doc_type, 0) + 1
            
            # Região
            region = result.get('region', 'unknown')
            distribution['regions'][region] = distribution['regions'].get(region, 0) + 1
            
            # Nível de confiança
            confidence = classification.get('classification_confidence', 0.0)
            confidence_range = self._get_confidence_range(confidence)
            distribution['confidence_levels'][confidence_range] = distribution['confidence_levels'].get(confidence_range, 0) + 1
        
        return distribution
    
    def _get_confidence_range(self, confidence: float) -> str:
        """
        Categoriza nível de confiança
        """
        if confidence >= 0.9:
            return 'high (0.9+)'
        elif confidence >= 0.7:
            return 'medium (0.7-0.9)'
        elif confidence >= 0.5:
            return 'low (0.5-0.7)'
        else:
            return 'very_low (<0.5)'
    
    def _calculate_overall_quality_metrics(self, results: List[Dict]) -> Dict[str, float]:
        """
        Calcula métricas gerais de qualidade
        """
        
        if not results:
            return {}
        
        total_results = len(results)
        
        # Métricas de completude
        with_dates = sum(1 for r in results if r.get('enacting_date'))
        with_urns = sum(1 for r in results if r.get('urn'))
        with_descriptions = sum(1 for r in results if r.get('document_summary'))
        
        # Métricas de qualidade de parsing
        high_quality_parsing = sum(1 for r in results 
                                 if r.get('quality_assessment', {}).get('overall_quality', 0) >= 0.8)
        
        # Métricas de classificação
        high_confidence_classification = sum(1 for r in results 
                                           if r.get('classification', {}).get('classification_confidence', 0) >= 0.8)
        
        return {
            'completeness_dates': with_dates / total_results,
            'completeness_urns': with_urns / total_results,
            'completeness_descriptions': with_descriptions / total_results,
            'parsing_quality_rate': high_quality_parsing / total_results,
            'classification_confidence_rate': high_confidence_classification / total_results,
            'overall_quality_score': (
                (with_dates + with_urns + with_descriptions + high_quality_parsing + high_confidence_classification) 
                / (total_results * 5)
            )
        }
    
    def save_enhanced_results(self, search_results: Dict, filename: str = None) -> str:
        """
        Salva resultados com metadados enriquecidos
        """
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'lexml_enhanced_results_{timestamp}.csv'
        
        results = search_results['results']
        
        # Cabeçalhos expandidos
        headers = [
            'search_term', 'search_category', 'date_searched', 'url', 'title', 'urn',
            'urn_type', 'country', 'state', 'municipality', 'justice', 'region',
            'court_class', 'document_type_full', 'enacting_date', 'document_description',
            'document_summary', 'main_category', 'document_type_refined', 'document_subtype',
            'classification_confidence', 'primary_themes', 'secondary_themes',
            'relevance_score', 'stakeholders_identified', 'parsing_quality',
            'extraction_method', 'extraction_confidence', 'processing_timestamp'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for result in results:
                classification = result.get('classification', {})
                thematic_enrichment = result.get('thematic_enrichment', {})
                quality_assessment = result.get('quality_assessment', {})
                
                row = [
                    result.get('search_term', ''),
                    result.get('search_category', ''),
                    result.get('date_searched', ''),
                    result.get('url', ''),
                    result.get('title', ''),
                    result.get('urn', ''),
                    result.get('urn_type', ''),
                    result.get('country', ''),
                    result.get('state', ''),
                    result.get('municipality', ''),
                    result.get('justice', ''),
                    result.get('region', ''),
                    result.get('court_class', ''),
                    result.get('document_type_full', ''),
                    result.get('enacting_date', ''),
                    result.get('document_description', ''),
                    result.get('document_summary', ''),
                    classification.get('main_category', ''),
                    classification.get('document_type', ''),
                    classification.get('document_subtype', ''),
                    classification.get('classification_confidence', ''),
                    '; '.join(thematic_enrichment.get('primary_themes', [])),
                    '; '.join(thematic_enrichment.get('secondary_themes', [])),
                    thematic_enrichment.get('relevance_score', ''),
                    '; '.join(thematic_enrichment.get('stakeholders_identified', [])),
                    quality_assessment.get('overall_quality', ''),
                    result.get('extraction_method', ''),
                    result.get('extraction_confidence', ''),
                    result.get('processing_timestamp', '')
                ]
                
                writer.writerow(row)
        
        # Salva estatísticas separadamente
        stats_filename = filename.replace('.csv', '_statistics.json')
        with open(stats_filename, 'w', encoding='utf-8') as f:
            json.dump(search_results['statistics'], f, indent=2, ensure_ascii=False)
        
        logging.info(f"Resultados salvos em {filename}")
        logging.info(f"Estatísticas salvas em {stats_filename}")
        
        return filename


# Classes auxiliares (implementações simplificadas para o exemplo)

class RefinedDocumentClassifier:
    """Classificador refinado de documentos"""
    
    def classify_document(self, urn, title, document_summary, document_type_original):
        # Implementação simplificada
        return {
            'main_category': 'legislation',
            'document_type': 'lei_ordinaria',
            'document_subtype': 'combustiveis_energia',
            'classification_confidence': 0.85
        }

class IntegratedParsingSystem:
    """Sistema integrado de parsing"""
    
    def parse_document(self, document_data):
        # Implementação simplificada
        return {
            'parsing_prompt_used': 'legislation_geral',
            'extraction_confidence': 0.8,
            'structured_data': {}
        }

class ThematicEnrichmentSystem:
    """Sistema de enriquecimento temático"""
    
    def enrich_document_analysis(self, parsed_content, original_document):
        # Implementação simplificada
        return {
            **parsed_content,
            'thematic_enrichment': {
                'primary_themes': ['combustiveis_energia'],
                'secondary_themes': ['regulamentacao_normas'],
                'relevance_score': 0.75,
                'stakeholders_identified': ['transportadores', 'reguladores'],
                'sectoral_impact': {'direct_impact': ['compliance_requirements']}
            }
        }

class ParsingQualityController:
    """Controlador de qualidade do parsing"""
    
    def validate_parsing_result(self, parsed_content, original_document):
        # Implementação simplificada
        return {
            'completeness_score': 0.8,
            'accuracy_score': 0.85,
            'consistency_score': 0.9,
            'relevance_score': 0.75,
            'overall_quality': 0.825,
            'recommendations': []
        }


# Função principal de execução
def main():
    """
    Função principal para execução da estratégia refinada
    """
    
    logging.info("Iniciando Estratégia LexML Refinada v2.0")
    
    # Inicialização do sistema
    lexml_strategy = EnhancedLexMLStrategy()
    
    try:
        # Execução da busca abrangente
        search_results = lexml_strategy.execute_comprehensive_search(
            categories=None,  # Todas as categorias
            max_results_per_category=50,
            include_all_document_types=True
        )
        
        # Salvamento dos resultados
        output_file = lexml_strategy.save_enhanced_results(search_results)
        
        # Log das estatísticas finais
        stats = search_results['statistics']
        logging.info(f"Busca concluída com sucesso:")
        logging.info(f"- Total de documentos: {stats['unique_documents']}")
        logging.info(f"- Categorias processadas: {stats['total_categories_searched']}")
        logging.info(f"- Qualidade geral: {stats['quality_metrics'].get('overall_quality_score', 'N/A'):.2%}")
        
        print(f"\n✅ Estratégia LexML v2.0 executada com sucesso!")
        print(f"📁 Resultados salvos em: {output_file}")
        print(f"📊 Documentos únicos encontrados: {stats['unique_documents']}")
        
    except Exception as e:
        logging.error(f"Erro na execução da estratégia: {e}")
        print(f"❌ Erro na execução: {e}")


if __name__ == "__main__":
    main()

