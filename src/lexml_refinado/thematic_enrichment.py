#!/usr/bin/env python3
"""
Sistema de Enriquecimento Temático para LexML
Enriquece documentos com análise temática baseada nos novos termos de busca

Autor: Manus AI
Data: 2025-07-14
Versão: 2.0
"""

import logging
from typing import Dict, List, Any, Tuple
from collections import Counter

logger = logging.getLogger(__name__)


class ThematicEnrichmentSystem:
    """
    Sistema de enriquecimento baseado nos novos termos de busca
    """
    
    def __init__(self):
        self.search_terms = self._load_enhanced_search_terms()
        self.thematic_categories = self._load_thematic_categories()
        self.stakeholder_patterns = self._load_stakeholder_patterns()
        
    def enrich_document_analysis(self, parsed_content: Dict[str, Any], 
                               original_document: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriquece análise com base nos novos termos de busca
        
        Args:
            parsed_content: Conteúdo já parseado
            original_document: Documento original
            
        Returns:
            Conteúdo enriquecido com análise temática
        """
        text_content = self._get_combined_text(original_document)
        
        # Identificação de temas específicos
        thematic_matches = self._identify_thematic_matches(text_content)
        
        # Classificação de relevância
        relevance_score = self._calculate_thematic_relevance(thematic_matches)
        
        # Identificação de stakeholders
        stakeholders = self._identify_stakeholders(text_content)
        
        # Análise de impacto setorial
        sectoral_impact = self._analyze_sectoral_impact(thematic_matches, text_content)
        
        # Análise de complexidade regulatória
        regulatory_complexity = self._assess_regulatory_complexity(thematic_matches)
        
        # Identificação de tendências emergentes
        emerging_trends = self._identify_emerging_trends(text_content)
        
        # Análise de alinhamento com programas governamentais
        program_alignment = self._analyze_program_alignment(text_content)
        
        # Enriquecimento do conteúdo parsed
        enriched_content = {
            **parsed_content,
            'thematic_enrichment': {
                'primary_themes': thematic_matches['primary'],
                'secondary_themes': thematic_matches['secondary'],
                'theme_scores': thematic_matches['scores'],
                'relevance_score': relevance_score,
                'stakeholders_identified': stakeholders,
                'sectoral_impact': sectoral_impact,
                'regulatory_complexity': regulatory_complexity,
                'emerging_trends': emerging_trends,
                'program_alignment': program_alignment,
                'enrichment_confidence': self._calculate_enrichment_confidence(thematic_matches)
            }
        }
        
        return enriched_content
    
    def _get_combined_text(self, document: Dict[str, Any]) -> str:
        """Combina título e resumo do documento para análise"""
        title = document.get('title', '')
        summary = document.get('document_summary', '')
        description = document.get('document_description', '')
        
        return f"{title} {summary} {description}".lower()
    
    def _identify_thematic_matches(self, text_content: str) -> Dict[str, Any]:
        """
        Identifica matches temáticos baseados nos novos termos
        """
        matches = {
            'primary': [],
            'secondary': [],
            'scores': {},
            'detailed_matches': {}
        }
        
        for category, terms in self.search_terms.items():
            # Conta ocorrências de cada termo
            term_matches = []
            for term in terms:
                if term.lower() in text_content:
                    term_matches.append(term)
            
            if term_matches:
                # Calcula score baseado na proporção de termos encontrados
                score = len(term_matches) / len(terms)
                matches['scores'][category] = score
                matches['detailed_matches'][category] = term_matches
                
                # Classifica como primário ou secundário
                if score > 0.3:
                    matches['primary'].append(category)
                elif score > 0.1:
                    matches['secondary'].append(category)
        
        # Ordena temas por score
        matches['primary'].sort(key=lambda x: matches['scores'].get(x, 0), reverse=True)
        matches['secondary'].sort(key=lambda x: matches['scores'].get(x, 0), reverse=True)
        
        return matches
    
    def _calculate_thematic_relevance(self, thematic_matches: Dict[str, Any]) -> float:
        """
        Calcula score de relevância baseado nos temas identificados
        """
        if not thematic_matches['scores']:
            return 0.0
        
        # Pesos para diferentes categorias
        category_weights = {
            'transporte_geral': 1.0,
            'combustiveis_energia': 0.95,
            'eficiencia_emissoes': 0.9,
            'tecnologia_inovacao': 0.85,
            'infraestrutura': 0.85,
            'regulamentacao_normas': 0.95,
            'incentivos_tributacao': 0.8,
            'programas_governamentais': 0.9,
            'maquinas_equipamentos': 0.75,
            'operacoes_servicos': 0.85
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for category, score in thematic_matches['scores'].items():
            weight = category_weights.get(category, 0.7)
            weighted_score += score * weight
            total_weight += weight
        
        # Normaliza o score
        if total_weight > 0:
            relevance_score = weighted_score / total_weight
        else:
            relevance_score = 0.0
        
        # Bonus por múltiplas categorias primárias
        if len(thematic_matches['primary']) > 2:
            relevance_score = min(1.0, relevance_score * 1.2)
        
        return round(relevance_score, 3)
    
    def _identify_stakeholders(self, text_content: str) -> List[str]:
        """
        Identifica stakeholders baseado no conteúdo
        """
        identified_stakeholders = []
        
        for stakeholder_type, patterns in self.stakeholder_patterns.items():
            if any(pattern in text_content for pattern in patterns):
                identified_stakeholders.append(stakeholder_type)
        
        return identified_stakeholders
    
    def _analyze_sectoral_impact(self, thematic_matches: Dict[str, Any], 
                               text_content: str) -> Dict[str, Any]:
        """
        Analisa impacto setorial baseado nos temas identificados
        """
        impact_analysis = {
            'direct_impact': [],
            'indirect_impact': [],
            'implementation_complexity': 'medium',
            'compliance_cost': 'medium',
            'timeline_urgency': 'medium',
            'affected_segments': []
        }
        
        # Análise de impacto direto por categoria
        impact_mapping = {
            'regulamentacao_normas': 'compliance_requirements',
            'incentivos_tributacao': 'financial_impact',
            'tecnologia_inovacao': 'technological_adaptation',
            'infraestrutura': 'infrastructure_investment',
            'eficiencia_emissoes': 'environmental_compliance',
            'combustiveis_energia': 'operational_changes'
        }
        
        for category in thematic_matches['primary']:
            if category in impact_mapping:
                impact_analysis['direct_impact'].append(impact_mapping[category])
        
        # Análise de segmentos afetados
        segment_keywords = {
            'rodoviário': ['rodoviario', 'caminhao', 'rodovia'],
            'urbano': ['urbano', 'cidade', 'municipal'],
            'interestadual': ['interestadual', 'estados'],
            'internacional': ['internacional', 'fronteira', 'exportacao'],
            'carga_pesada': ['carga pesada', 'bitrem', 'rodotrem'],
            'distribuição': ['distribuicao', 'entrega', 'last mile']
        }
        
        for segment, keywords in segment_keywords.items():
            if any(keyword in text_content for keyword in keywords):
                impact_analysis['affected_segments'].append(segment)
        
        # Análise de complexidade
        complexity_indicators = ['regulamentacao_normas', 'programas_governamentais', 
                               'tecnologia_inovacao']
        complexity_score = sum(1 for indicator in complexity_indicators 
                             if indicator in thematic_matches['primary'])
        
        if complexity_score >= 2:
            impact_analysis['implementation_complexity'] = 'high'
        elif complexity_score == 0:
            impact_analysis['implementation_complexity'] = 'low'
        
        # Análise de custo de compliance
        cost_indicators = ['tecnologia_inovacao', 'infraestrutura', 'eficiencia_emissoes']
        cost_score = sum(1 for indicator in cost_indicators 
                        if indicator in thematic_matches['primary'])
        
        if cost_score >= 2:
            impact_analysis['compliance_cost'] = 'high'
        elif cost_score == 0:
            impact_analysis['compliance_cost'] = 'low'
        
        # Análise de urgência temporal
        urgency_keywords = ['imediato', 'urgente', 'prazo', 'vigencia', 'partir de']
        if any(keyword in text_content for keyword in urgency_keywords):
            impact_analysis['timeline_urgency'] = 'high'
        
        return impact_analysis
    
    def _assess_regulatory_complexity(self, thematic_matches: Dict[str, Any]) -> Dict[str, Any]:
        """
        Avalia complexidade regulatória do documento
        """
        complexity_assessment = {
            'level': 'medium',
            'factors': [],
            'coordination_required': [],
            'implementation_challenges': []
        }
        
        # Fatores de complexidade
        if 'regulamentacao_normas' in thematic_matches['primary']:
            complexity_assessment['factors'].append('multiple_regulatory_requirements')
        
        if 'tecnologia_inovacao' in thematic_matches['primary']:
            complexity_assessment['factors'].append('technological_adaptation_needed')
        
        if 'incentivos_tributacao' in thematic_matches['primary']:
            complexity_assessment['factors'].append('fiscal_coordination_required')
        
        # Coordenação necessária entre órgãos
        organ_categories = {
            'combustiveis_energia': ['ANP', 'MME'],
            'eficiencia_emissoes': ['IBAMA', 'MMA'],
            'infraestrutura': ['ANTT', 'DNIT'],
            'regulamentacao_normas': ['ANTT', 'CONTRAN'],
            'incentivos_tributacao': ['RFB', 'CONFAZ']
        }
        
        for category in thematic_matches['primary']:
            if category in organ_categories:
                complexity_assessment['coordination_required'].extend(
                    organ_categories[category]
                )
        
        # Remove duplicatas
        complexity_assessment['coordination_required'] = list(
            set(complexity_assessment['coordination_required'])
        )
        
        # Determina nível de complexidade
        factor_count = len(complexity_assessment['factors'])
        organ_count = len(complexity_assessment['coordination_required'])
        
        if factor_count >= 3 or organ_count >= 4:
            complexity_assessment['level'] = 'high'
        elif factor_count <= 1 and organ_count <= 1:
            complexity_assessment['level'] = 'low'
        
        # Identifica desafios de implementação
        if complexity_assessment['level'] == 'high':
            complexity_assessment['implementation_challenges'] = [
                'inter-agency_coordination',
                'multiple_compliance_requirements',
                'phased_implementation_needed'
            ]
        
        return complexity_assessment
    
    def _identify_emerging_trends(self, text_content: str) -> List[str]:
        """
        Identifica tendências emergentes no documento
        """
        emerging_trends = []
        
        # Palavras-chave de tendências emergentes
        trend_keywords = {
            'eletrificação': ['eletrico', 'eletrificacao', 'bateria', 'carregamento'],
            'digitalização': ['digital', 'conectado', 'iot', 'telematica', 'dados'],
            'sustentabilidade': ['sustentavel', 'verde', 'carbono neutro', 'esg'],
            'autonomia': ['autonomo', 'automatizado', 'sem motorista'],
            'economia_compartilhada': ['compartilhado', 'sharing', 'colaborativo'],
            'hidrogênio': ['hidrogenio', 'h2', 'celula combustivel'],
            'intermodalidade': ['intermodal', 'multimodal', 'integracao modal'],
            'última_milha': ['ultima milha', 'last mile', 'entrega urbana']
        }
        
        for trend, keywords in trend_keywords.items():
            if any(keyword in text_content for keyword in keywords):
                emerging_trends.append(trend)
        
        return emerging_trends
    
    def _analyze_program_alignment(self, text_content: str) -> Dict[str, List[str]]:
        """
        Analisa alinhamento com programas governamentais
        """
        program_alignment = {
            'aligned_programs': [],
            'policy_objectives': []
        }
        
        # Programas governamentais específicos
        government_programs = {
            'Rota 2030': ['rota 2030', 'rota2030'],
            'PATEN': ['paten', 'programa de aceleracao'],
            'Renovabio': ['renovabio', 'cbio'],
            'Combustível do Futuro': ['combustivel do futuro', 'lei do combustivel'],
            'BR do Mar': ['br do mar', 'cabotagem'],
            'Plano Nacional de Logística': ['pnl', 'plano nacional logistica']
        }
        
        for program, keywords in government_programs.items():
            if any(keyword in text_content for keyword in keywords):
                program_alignment['aligned_programs'].append(program)
        
        # Objetivos de política pública
        policy_keywords = {
            'descarbonização': ['descarbonizacao', 'baixo carbono', 'net zero'],
            'eficiência_logística': ['eficiencia logistica', 'produtividade'],
            'segurança_viária': ['seguranca viaria', 'reducao acidentes'],
            'competitividade': ['competitividade', 'custo brasil'],
            'inovação_tecnológica': ['inovacao', 'tecnologia', 'modernizacao'],
            'integração_regional': ['integracao', 'corredores', 'conectividade']
        }
        
        for objective, keywords in policy_keywords.items():
            if any(keyword in text_content for keyword in keywords):
                program_alignment['policy_objectives'].append(objective)
        
        return program_alignment
    
    def _calculate_enrichment_confidence(self, thematic_matches: Dict[str, Any]) -> float:
        """
        Calcula confiança do enriquecimento temático
        """
        # Fatores de confiança
        has_primary_themes = len(thematic_matches['primary']) > 0
        has_multiple_themes = len(thematic_matches['primary']) + len(thematic_matches['secondary']) > 2
        has_high_scores = any(score > 0.5 for score in thematic_matches['scores'].values())
        
        confidence = 0.5  # Base
        
        if has_primary_themes:
            confidence += 0.2
        
        if has_multiple_themes:
            confidence += 0.15
        
        if has_high_scores:
            confidence += 0.15
        
        return round(confidence, 2)
    
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
    
    def _load_thematic_categories(self) -> List[str]:
        """
        Carrega categorias temáticas principais
        """
        return [
            'Combustíveis e Energia',
            'Eficiência Energética e Emissões',
            'Tecnologia e Inovação',
            'Infraestrutura',
            'Regulamentação e Normas',
            'Incentivos e Tributação',
            'Programas Governamentais',
            'Máquinas e Equipamentos',
            'Operações e Serviços',
            'Transporte Geral'
        ]
    
    def _load_stakeholder_patterns(self) -> Dict[str, List[str]]:
        """
        Carrega padrões para identificação de stakeholders
        """
        return {
            'transportadores': [
                'transportador', 'caminhoneiro', 'motorista', 
                'empresa de transporte', 'transportadora'
            ],
            'embarcadores': [
                'embarcador', 'remetente', 'expedidor', 
                'indústria', 'produtor'
            ],
            'reguladores': [
                'antt', 'anp', 'aneel', 'ana', 'contran', 
                'ibama', 'mma', 'mme', 'ministério'
            ],
            'fornecedores': [
                'fabricante', 'montadora', 'distribuidor', 
                'fornecedor', 'concessionária'
            ],
            'usuarios_finais': [
                'consumidor', 'destinatário', 'cliente final', 
                'varejo', 'comércio'
            ],
            'sociedade_civil': [
                'população', 'comunidade', 'sociedade civil', 
                'ong', 'associação'
            ],
            'instituições_financeiras': [
                'banco', 'financiadora', 'investidor', 
                'fundo', 'bndes'
            ],
            'academia': [
                'universidade', 'pesquisador', 'instituto', 
                'centro de pesquisa'
            ]
        }