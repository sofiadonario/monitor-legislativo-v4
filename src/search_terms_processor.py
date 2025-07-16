#!/usr/bin/env python3
"""
Processador de Termos de Busca com Categorias Refinadas
Implementa busca booleana e categorização temática baseada na documentação LexML
"""

import re
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
import pandas as pd
from dataclasses import dataclass, asdict

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SearchResult:
    """Estrutura para resultado de busca"""
    term: str
    category: str
    matches: int
    relevance_score: float
    documents: List[Dict]

class EnhancedSearchTermsProcessor:
    """
    Processador aprimorado para os novos termos de busca
    Implementa busca booleana e categorização temática
    """
    
    def __init__(self):
        self.search_categories = self._load_search_categories()
        self.boolean_combinations = self._load_boolean_combinations()
        self.legal_terms = self._load_legal_terms()
        
    def _load_search_categories(self) -> Dict[str, List[str]]:
        """
        Carrega as 10 categorias de termos de busca
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
    
    def _load_boolean_combinations(self) -> List[str]:
        """
        Carrega combinações booleanas sugeridas
        """
        return [
            '("transporte de carga" OR "veículos pesados") AND ("gás natural" OR biometano OR biodiesel)',
            '(caminhão OR "veículo pesado") AND (incentivo OR benefício OR isenção)',
            '("eficiência energética" OR emissões) AND ("transporte rodoviário" OR logística)',
            '(Rota 2030 OR Paten) AND (transporte OR logística OR carga)',
            '("combustível sustentável" OR hidrogênio) AND (transporte OR veículos)',
            '(ANTT OR CONTRAN) AND (regulamentação OR normas)',
            '("veículos autônomos" OR telemetria) AND transporte',
            '(biometano OR "gás natural") AND ("postos de abastecimento" OR infraestrutura)',
            '("transição energética" OR descarbonização) AND transporte',
            '(IPI OR ICMS) AND ("veículos pesados" OR caminhão)'
        ]
    
    def _load_legal_terms(self) -> List[str]:
        """
        Carrega termos legais para combinação
        """
        return [
            'lei', 'decreto', 'portaria', 'resolução', 'medida provisória',
            'projeto de lei', 'instrução normativa', 'emenda constitucional',
            'decreto legislativo', 'lei complementar', 'súmula', 'acordão',
            'decisão', 'sentença', 'recurso', 'apelação'
        ]
    
    def generate_search_query(self, categories: List[str] = None, 
                            include_legal_terms: bool = True,
                            query_type: str = 'comprehensive') -> str:
        """
        Gera consulta de busca baseada nas categorias selecionadas
        """
        
        if categories is None:
            categories = list(self.search_categories.keys())
        
        if query_type == 'comprehensive':
            return self._generate_comprehensive_query(categories, include_legal_terms)
        elif query_type == 'boolean':
            return self._generate_boolean_query(categories, include_legal_terms)
        elif query_type == 'simple':
            return self._generate_simple_query(categories)
        else:
            raise ValueError(f"Tipo de query inválido: {query_type}")
    
    def _generate_comprehensive_query(self, categories: List[str], 
                                    include_legal_terms: bool) -> str:
        """
        Gera consulta de busca abrangente
        """
        
        # Termos por categoria
        category_terms = []
        for category in categories:
            if category in self.search_categories:
                terms = self.search_categories[category]
                category_query = '(' + ' OR '.join(f'"{term}"' for term in terms) + ')'
                category_terms.append(category_query)
        
        # Combinação das categorias
        main_query = ' OR '.join(category_terms)
        
        # Adição de termos legais se solicitado
        if include_legal_terms:
            legal_query = '(' + ' OR '.join(self.legal_terms) + ')'
            main_query = f'({main_query}) AND {legal_query}'
        
        return main_query
    
    def _generate_boolean_query(self, categories: List[str], 
                              include_legal_terms: bool) -> str:
        """
        Gera consulta booleana específica
        """
        
        # Selecionar combinações relevantes para as categorias
        relevant_combinations = []
        
        for combo in self.boolean_combinations:
            for category in categories:
                category_terms = self.search_categories.get(category, [])
                if any(term.lower() in combo.lower() for term in category_terms):
                    relevant_combinations.append(combo)
                    break
        
        if not relevant_combinations:
            return self._generate_comprehensive_query(categories, include_legal_terms)
        
        # Combinar queries booleanas
        combined_query = ' OR '.join(f'({combo})' for combo in relevant_combinations)
        
        if include_legal_terms:
            legal_query = '(' + ' OR '.join(self.legal_terms) + ')'
            combined_query = f'({combined_query}) AND {legal_query}'
        
        return combined_query
    
    def _generate_simple_query(self, categories: List[str]) -> str:
        """
        Gera consulta simples com termos principais
        """
        
        main_terms = []
        for category in categories:
            if category in self.search_categories:
                # Pegar os 3 termos principais de cada categoria
                terms = self.search_categories[category][:3]
                main_terms.extend(terms)
        
        return ' OR '.join(f'"{term}"' for term in main_terms)
    
    def categorize_search_results(self, results: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Categoriza resultados de busca por tema
        """
        
        categorized_results = {category: [] for category in self.search_categories.keys()}
        categorized_results['uncategorized'] = []
        
        for result in results:
            text_content = f"{result.get('title', '')} {result.get('document_summary', '')}".lower()
            
            # Identificar categorias relevantes
            best_category = None
            best_score = 0
            
            for category, terms in self.search_categories.items():
                matches = sum(1 for term in terms if term.lower() in text_content)
                relevance_score = matches / len(terms) if terms else 0
                
                if relevance_score > best_score:
                    best_score = relevance_score
                    best_category = category
            
            # Adicionar à melhor categoria ou uncategorized
            if best_category and best_score > 0.1:  # Threshold mínimo
                categorized_results[best_category].append({
                    **result,
                    'category_matches': int(best_score * len(self.search_categories[best_category])),
                    'category_relevance': best_score,
                    'assigned_category': best_category
                })
            else:
                categorized_results['uncategorized'].append(result)
        
        return categorized_results
    
    def analyze_term_effectiveness(self, results: List[Dict]) -> Dict[str, Dict]:
        """
        Analisa efetividade dos termos de busca
        """
        
        effectiveness_analysis = {}
        
        for category, terms in self.search_categories.items():
            category_analysis = {
                'total_terms': len(terms),
                'effective_terms': 0,
                'term_performance': {},
                'category_coverage': 0,
                'average_relevance': 0
            }
            
            relevance_scores = []
            
            for term in terms:
                term_matches = 0
                term_relevance = 0
                
                for result in results:
                    text_content = f"{result.get('title', '')} {result.get('document_summary', '')}".lower()
                    
                    if term.lower() in text_content:
                        term_matches += 1
                        # Calcular relevância baseada na frequência e posição
                        term_relevance += text_content.count(term.lower())
                
                if term_matches > 0:
                    category_analysis['effective_terms'] += 1
                    relevance_scores.append(term_relevance / max(term_matches, 1))
                
                category_analysis['term_performance'][term] = {
                    'matches': term_matches,
                    'relevance': term_relevance,
                    'effectiveness': term_matches / len(results) if results else 0
                }
            
            # Calcular métricas da categoria
            category_analysis['category_coverage'] = category_analysis['effective_terms'] / category_analysis['total_terms']
            category_analysis['average_relevance'] = sum(relevance_scores) / len(relevance_scores) if relevance_scores else 0
            
            effectiveness_analysis[category] = category_analysis
        
        return effectiveness_analysis
    
    def suggest_term_improvements(self, effectiveness_analysis: Dict) -> Dict[str, List[str]]:
        """
        Sugere melhorias nos termos de busca
        """
        
        suggestions = {}
        
        for category, analysis in effectiveness_analysis.items():
            category_suggestions = []
            
            # Termos com baixa efetividade
            low_performing_terms = [
                term for term, perf in analysis['term_performance'].items()
                if perf['effectiveness'] < 0.05
            ]
            
            if low_performing_terms:
                category_suggestions.append(f"Revisar termos com baixa efetividade: {', '.join(low_performing_terms[:3])}")
            
            # Cobertura da categoria
            if analysis['category_coverage'] < 0.5:
                category_suggestions.append("Adicionar mais termos variados para melhor cobertura")
            
            # Relevância média
            if analysis['average_relevance'] < 1.0:
                category_suggestions.append("Considerar termos mais específicos para maior relevância")
            
            # Sugestões específicas por categoria
            if category == 'combustiveis_energia' and analysis['category_coverage'] < 0.7:
                category_suggestions.append("Adicionar termos emergentes: 'e-fuel', 'combustível sintético', 'amônia verde'")
            
            elif category == 'tecnologia_inovacao' and analysis['category_coverage'] < 0.6:
                category_suggestions.append("Incluir: 'inteligência artificial', 'blockchain', 'IoT transporte'")
            
            elif category == 'programas_governamentais' and analysis['category_coverage'] < 0.5:
                category_suggestions.append("Atualizar com programas recentes do governo")
            
            suggestions[category] = category_suggestions
        
        return suggestions
    
    def generate_search_report(self, results: List[Dict], output_file: str = None) -> str:
        """
        Gera relatório completo de análise de busca
        """
        
        if not output_file:
            output_file = f"search_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Categorizar resultados
        categorized_results = self.categorize_search_results(results)
        
        # Analisar efetividade
        effectiveness_analysis = self.analyze_term_effectiveness(results)
        
        # Sugerir melhorias
        suggestions = self.suggest_term_improvements(effectiveness_analysis)
        
        # Compilar relatório
        report = {
            'metadata': {
                'generation_date': datetime.now().isoformat(),
                'total_results': len(results),
                'categories_analyzed': len(self.search_categories),
                'processor_version': '1.0'
            },
            'search_summary': {
                'total_categories': len(self.search_categories),
                'total_terms': sum(len(terms) for terms in self.search_categories.values()),
                'boolean_combinations': len(self.boolean_combinations),
                'legal_terms': len(self.legal_terms)
            },
            'categorization_results': {
                category: {
                    'count': len(docs),
                    'percentage': len(docs) / len(results) * 100 if results else 0
                }
                for category, docs in categorized_results.items()
            },
            'effectiveness_analysis': effectiveness_analysis,
            'improvement_suggestions': suggestions,
            'top_performing_terms': self._get_top_performing_terms(effectiveness_analysis),
            'sample_results_by_category': {
                category: docs[:3] for category, docs in categorized_results.items()
                if docs
            }
        }
        
        # Salvar relatório
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Relatório de análise de busca salvo em: {output_file}")
        return output_file
    
    def _get_top_performing_terms(self, effectiveness_analysis: Dict) -> Dict[str, List[Dict]]:
        """
        Identifica termos com melhor performance
        """
        
        top_terms = {}
        
        for category, analysis in effectiveness_analysis.items():
            # Ordenar termos por efetividade
            sorted_terms = sorted(
                analysis['term_performance'].items(),
                key=lambda x: x[1]['effectiveness'],
                reverse=True
            )
            
            # Pegar top 5
            top_terms[category] = [
                {
                    'term': term,
                    'effectiveness': perf['effectiveness'],
                    'matches': perf['matches'],
                    'relevance': perf['relevance']
                }
                for term, perf in sorted_terms[:5]
            ]
        
        return top_terms
    
    def create_custom_search_strategy(self, target_categories: List[str],
                                    priority_terms: List[str] = None,
                                    exclude_terms: List[str] = None) -> Dict:
        """
        Cria estratégia de busca personalizada
        """
        
        strategy = {
            'target_categories': target_categories,
            'priority_terms': priority_terms or [],
            'exclude_terms': exclude_terms or [],
            'search_queries': {},
            'expected_coverage': {}
        }
        
        # Gerar queries para cada categoria alvo
        for category in target_categories:
            if category in self.search_categories:
                category_terms = self.search_categories[category].copy()
                
                # Adicionar termos prioritários
                if priority_terms:
                    category_terms.extend(priority_terms)
                
                # Remover termos excluídos
                if exclude_terms:
                    category_terms = [term for term in category_terms if term not in exclude_terms]
                
                # Gerar query específica
                query = ' OR '.join(f'"{term}"' for term in category_terms)
                strategy['search_queries'][category] = query
                
                # Estimar cobertura esperada
                strategy['expected_coverage'][category] = len(category_terms) / len(self.search_categories[category])
        
        return strategy
    
    def validate_search_terms(self) -> Dict[str, List[str]]:
        """
        Valida termos de busca quanto a duplicatas e inconsistências
        """
        
        validation_issues = {
            'duplicates': [],
            'similar_terms': [],
            'missing_variations': [],
            'inconsistent_formatting': []
        }
        
        # Verificar duplicatas exatas
        all_terms = []
        for category, terms in self.search_categories.items():
            for term in terms:
                all_terms.append((term, category))
        
        seen_terms = set()
        for term, category in all_terms:
            if term in seen_terms:
                validation_issues['duplicates'].append(f"'{term}' duplicado")
            else:
                seen_terms.add(term)
        
        # Verificar termos similares
        for i, (term1, cat1) in enumerate(all_terms):
            for j, (term2, cat2) in enumerate(all_terms[i+1:], i+1):
                if self._are_similar_terms(term1, term2):
                    validation_issues['similar_terms'].append(f"'{term1}' similar a '{term2}'")
        
        # Verificar variações em falta
        for category, terms in self.search_categories.items():
            for term in terms:
                variations = self._generate_term_variations(term)
                missing = [var for var in variations if var not in terms]
                if missing:
                    validation_issues['missing_variations'].extend(
                        [f"'{term}' pode ter variação '{var}'" for var in missing[:2]]
                    )
        
        # Verificar formatação inconsistente
        for category, terms in self.search_categories.items():
            for term in terms:
                if self._has_formatting_issues(term):
                    validation_issues['inconsistent_formatting'].append(
                        f"'{term}' tem problemas de formatação"
                    )
        
        return validation_issues
    
    def _are_similar_terms(self, term1: str, term2: str) -> bool:
        """
        Verifica se dois termos são similares
        """
        
        # Normalizar termos
        norm1 = re.sub(r'\s+', ' ', term1.lower().strip())
        norm2 = re.sub(r'\s+', ' ', term2.lower().strip())
        
        # Verificar se um está contido no outro
        return norm1 in norm2 or norm2 in norm1
    
    def _generate_term_variations(self, term: str) -> List[str]:
        """
        Gera variações possíveis de um termo
        """
        
        variations = []
        
        # Variações de plural/singular
        if term.endswith('s'):
            variations.append(term[:-1])
        else:
            variations.append(term + 's')
        
        # Variações com hífens
        if ' ' in term:
            variations.append(term.replace(' ', '-'))
        if '-' in term:
            variations.append(term.replace('-', ' '))
        
        # Variações de acentos (exemplos básicos)
        accent_variations = {
            'ção': 'cao',
            'ção': 'cão',
            'ú': 'u',
            'é': 'e',
            'ó': 'o',
            'á': 'a'
        }
        
        for accented, unaccented in accent_variations.items():
            if accented in term:
                variations.append(term.replace(accented, unaccented))
        
        return variations
    
    def _has_formatting_issues(self, term: str) -> bool:
        """
        Verifica se um termo tem problemas de formatação
        """
        
        issues = [
            term.startswith(' ') or term.endswith(' '),  # Espaços extras
            '  ' in term,  # Espaços duplos
            term != term.strip(),  # Espaços nas pontas
            any(c.isupper() for c in term[1:]) and not term.isupper()  # Capitalização inconsistente
        ]
        
        return any(issues)
    
    def export_search_terms(self, format: str = 'json', output_file: str = None) -> str:
        """
        Exporta termos de busca em diferentes formatos
        """
        
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"search_terms_{timestamp}.{format}"
        
        if format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.search_categories, f, ensure_ascii=False, indent=2)
        
        elif format == 'csv':
            rows = []
            for category, terms in self.search_categories.items():
                for term in terms:
                    rows.append({'category': category, 'term': term})
            
            df = pd.DataFrame(rows)
            df.to_csv(output_file, index=False, encoding='utf-8')
        
        elif format == 'txt':
            with open(output_file, 'w', encoding='utf-8') as f:
                for category, terms in self.search_categories.items():
                    f.write(f"# {category.upper()}\n")
                    for term in terms:
                        f.write(f"- {term}\n")
                    f.write("\n")
        
        else:
            raise ValueError(f"Formato não suportado: {format}")
        
        logger.info(f"Termos de busca exportados em: {output_file}")
        return output_file


def main():
    """Função principal para teste"""
    
    # Exemplo de uso
    processor = EnhancedSearchTermsProcessor()
    
    # Gerar query abrangente
    comprehensive_query = processor.generate_search_query(
        categories=['combustiveis_energia', 'tecnologia_inovacao'],
        include_legal_terms=True,
        query_type='comprehensive'
    )
    
    print("Query Abrangente:")
    print(comprehensive_query)
    print("\n" + "="*50 + "\n")
    
    # Gerar query booleana
    boolean_query = processor.generate_search_query(
        categories=['combustiveis_energia', 'incentivos_tributacao'],
        include_legal_terms=True,
        query_type='boolean'
    )
    
    print("Query Booleana:")
    print(boolean_query)
    print("\n" + "="*50 + "\n")
    
    # Validar termos
    validation_issues = processor.validate_search_terms()
    print("Problemas de Validação:")
    for issue_type, issues in validation_issues.items():
        if issues:
            print(f"{issue_type}: {len(issues)} problemas")
            for issue in issues[:3]:  # Mostrar apenas os primeiros 3
                print(f"  - {issue}")
    
    # Exportar termos
    output_file = processor.export_search_terms(format='json')
    print(f"\nTermos exportados em: {output_file}")


if __name__ == "__main__":
    main()