#!/usr/bin/env python3
"""
Sistema de Controle de Qualidade para Parsing LexML
Valida e controla a qualidade das extrações de dados

Autor: Manus AI
Data: 2025-07-14
Versão: 2.0
"""

import re
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ParsingQualityController:
    """
    Sistema de controle de qualidade para parsing
    """
    
    def __init__(self):
        self.quality_metrics = {
            'completeness': 0.0,
            'accuracy': 0.0,
            'consistency': 0.0,
            'relevance': 0.0
        }
        
        self.validation_rules = self._load_validation_rules()
        self.quality_thresholds = self._load_quality_thresholds()
    
    def validate_parsing_result(self, parsed_content: Dict[str, Any], 
                              original_document: Dict[str, Any]) -> Dict[str, Any]:
        """
        Valida qualidade do parsing executado
        
        Args:
            parsed_content: Conteúdo parseado
            original_document: Documento original
            
        Returns:
            Resultados da validação com scores e recomendações
        """
        validation_results = {
            'completeness_score': self._check_completeness(parsed_content),
            'accuracy_score': self._check_accuracy(parsed_content, original_document),
            'consistency_score': self._check_consistency(parsed_content),
            'relevance_score': self._check_relevance(parsed_content),
            'overall_quality': 0.0,
            'quality_grade': 'C',
            'critical_issues': [],
            'warnings': [],
            'recommendations': [],
            'validation_timestamp': datetime.now().isoformat()
        }
        
        # Cálculo da qualidade geral
        validation_results['overall_quality'] = self._calculate_overall_quality(
            validation_results
        )
        
        # Determinação da nota de qualidade
        validation_results['quality_grade'] = self._determine_quality_grade(
            validation_results['overall_quality']
        )
        
        # Identificação de problemas críticos
        validation_results['critical_issues'] = self._identify_critical_issues(
            validation_results, parsed_content, original_document
        )
        
        # Geração de avisos
        validation_results['warnings'] = self._generate_warnings(
            validation_results, parsed_content
        )
        
        # Geração de recomendações
        validation_results['recommendations'] = self._generate_recommendations(
            validation_results
        )
        
        return validation_results
    
    def _check_completeness(self, parsed_content: Dict[str, Any]) -> float:
        """
        Verifica completude das informações extraídas
        """
        required_fields = [
            'document_identification',
            'thematic_classification', 
            'content_analysis',
            'regulatory_impact'
        ]
        
        structured_data = parsed_content.get('structured_data', {})
        
        # Verifica presença dos campos obrigatórios
        field_scores = []
        for field in required_fields:
            if field in structured_data and structured_data[field]:
                field_scores.append(1.0)
            else:
                field_scores.append(0.0)
        
        # Verifica subcomponentes importantes
        identification = structured_data.get('document_identification', {})
        id_completeness = self._check_identification_completeness(identification)
        
        classification = structured_data.get('thematic_classification', {})
        class_completeness = self._check_classification_completeness(classification)
        
        # Score final ponderado
        base_completeness = sum(field_scores) / len(field_scores)
        detail_completeness = (id_completeness + class_completeness) / 2
        
        return round((base_completeness * 0.7 + detail_completeness * 0.3), 2)
    
    def _check_identification_completeness(self, identification: Dict[str, Any]) -> float:
        """Verifica completude da identificação do documento"""
        key_fields = ['tipo_norma', 'data_publicacao', 'orgao_emissor', 'esfera']
        
        completed = sum(1 for field in key_fields 
                       if field in identification and identification[field])
        
        return completed / len(key_fields)
    
    def _check_classification_completeness(self, classification: Dict[str, Any]) -> float:
        """Verifica completude da classificação temática"""
        key_fields = ['categoria_principal']
        
        completed = sum(1 for field in key_fields 
                       if field in classification and classification[field])
        
        return completed / len(key_fields)
    
    def _check_accuracy(self, parsed_content: Dict[str, Any], 
                       original_document: Dict[str, Any]) -> float:
        """
        Verifica precisão das informações extraídas
        """
        accuracy_checks = []
        
        # Verificar se a data extraída está no formato correto
        date_accuracy = self._validate_date_format(parsed_content, original_document)
        accuracy_checks.append(date_accuracy)
        
        # Verificar se o tipo de documento é consistente com a URN
        type_accuracy = self._validate_document_type_consistency(
            parsed_content, original_document
        )
        accuracy_checks.append(type_accuracy)
        
        # Verificar se o órgão emissor é consistente
        organ_accuracy = self._validate_organ_consistency(
            parsed_content, original_document
        )
        accuracy_checks.append(organ_accuracy)
        
        # Verificar se os temas são consistentes com o conteúdo
        theme_accuracy = self._validate_theme_consistency(
            parsed_content, original_document
        )
        accuracy_checks.append(theme_accuracy)
        
        return round(sum(accuracy_checks) / len(accuracy_checks), 2)
    
    def _validate_date_format(self, parsed_content: Dict[str, Any], 
                            original_document: Dict[str, Any]) -> float:
        """Valida formato da data"""
        try:
            structured_data = parsed_content.get('structured_data', {})
            identification = structured_data.get('document_identification', {})
            date_str = identification.get('data_publicacao', '')
            
            if not date_str:
                return 0.5  # Sem data é problema, mas não erro de formato
            
            # Verifica formato ISO (YYYY-MM-DD)
            if re.match(r'\d{4}-\d{2}-\d{2}', date_str):
                return 1.0
            
            # Verifica formato brasileiro (DD/MM/YYYY)
            if re.match(r'\d{2}/\d{2}/\d{4}', date_str):
                return 0.9
            
            return 0.3  # Formato não reconhecido
            
        except Exception:
            return 0.0
    
    def _validate_document_type_consistency(self, parsed_content: Dict[str, Any], 
                                          original_document: Dict[str, Any]) -> float:
        """Valida consistência do tipo de documento com URN"""
        try:
            urn = original_document.get('urn', '').lower()
            
            structured_data = parsed_content.get('structured_data', {})
            identification = structured_data.get('document_identification', {})
            doc_type = identification.get('tipo_norma', '').lower()
            
            if not urn or not doc_type:
                return 0.5
            
            # Mapeamento de tipos esperados na URN
            type_mapping = {
                'lei': ['lei ordinária', 'lei complementar'],
                'decreto': ['decreto', 'decreto presidencial'],
                'portaria': ['portaria', 'portaria ministerial'],
                'resolucao': ['resolução']
            }
            
            for urn_pattern, expected_types in type_mapping.items():
                if urn_pattern in urn:
                    if any(exp_type in doc_type for exp_type in expected_types):
                        return 1.0
                    else:
                        return 0.3
            
            return 0.7  # Tipo não mapeado, mas não necessariamente erro
            
        except Exception:
            return 0.0
    
    def _validate_organ_consistency(self, parsed_content: Dict[str, Any], 
                                  original_document: Dict[str, Any]) -> float:
        """Valida consistência do órgão emissor"""
        try:
            title = original_document.get('title', '').upper()
            
            structured_data = parsed_content.get('structured_data', {})
            identification = structured_data.get('document_identification', {})
            organ = identification.get('orgao_emissor', '').upper()
            
            if not organ or organ == 'ÓRGÃO NÃO IDENTIFICADO':
                return 0.5
            
            # Verifica se o órgão aparece no título
            if organ in title:
                return 1.0
            
            # Verifica siglas comuns
            organ_mapping = {
                'ANTT': 'AGÊNCIA NACIONAL DE TRANSPORTES TERRESTRES',
                'ANP': 'AGÊNCIA NACIONAL DO PETRÓLEO',
                'CONTRAN': 'CONSELHO NACIONAL DE TRÂNSITO'
            }
            
            for acronym, full_name in organ_mapping.items():
                if acronym in title and (acronym in organ or full_name in organ):
                    return 1.0
            
            return 0.7  # Órgão identificado mas não confirmado no título
            
        except Exception:
            return 0.0
    
    def _validate_theme_consistency(self, parsed_content: Dict[str, Any], 
                                  original_document: Dict[str, Any]) -> float:
        """Valida consistência dos temas com o conteúdo"""
        try:
            text_content = f"{original_document.get('title', '')} {original_document.get('document_summary', '')}".lower()
            
            structured_data = parsed_content.get('structured_data', {})
            classification = structured_data.get('thematic_classification', {})
            main_theme = classification.get('categoria_principal', '')
            
            if not main_theme:
                return 0.5
            
            # Palavras-chave por tema
            theme_keywords = {
                'Combustíveis e Energia': ['combustível', 'energia', 'diesel', 'gasolina', 'etanol'],
                'Transporte Geral': ['transporte', 'carga', 'caminhão', 'veículo', 'frete'],
                'Regulamentação e Normas': ['regulamentação', 'norma', 'licenciamento', 'registro'],
                'Tecnologia e Inovação': ['tecnologia', 'inovação', 'digital', 'eletrônico']
            }
            
            keywords = theme_keywords.get(main_theme, [])
            if any(keyword in text_content for keyword in keywords):
                return 1.0
            
            return 0.6  # Tema não confirmado mas pode estar correto
            
        except Exception:
            return 0.0
    
    def _check_consistency(self, parsed_content: Dict[str, Any]) -> float:
        """
        Verifica consistência interna dos dados
        """
        consistency_checks = []
        
        # Verificar se classificação está consistente
        classification_consistency = self._check_classification_consistency(parsed_content)
        consistency_checks.append(classification_consistency)
        
        # Verificar se dados de implementação são consistentes
        implementation_consistency = self._check_implementation_consistency(parsed_content)
        consistency_checks.append(implementation_consistency)
        
        # Verificar se enriquecimento temático é consistente
        thematic_consistency = self._check_thematic_consistency(parsed_content)
        consistency_checks.append(thematic_consistency)
        
        return round(sum(consistency_checks) / len(consistency_checks), 2)
    
    def _check_classification_consistency(self, parsed_content: Dict[str, Any]) -> float:
        """Verifica consistência da classificação"""
        try:
            classification = parsed_content.get('classification', {})
            main_category = classification.get('main_category', '')
            document_type = classification.get('document_type', '')
            
            # Verifica se o tipo é consistente com a categoria
            if main_category == 'legislation':
                if any(word in document_type for word in ['lei', 'decreto', 'portaria']):
                    return 1.0
            elif main_category == 'jurisprudence':
                if any(word in document_type for word in ['stf', 'stj', 'trf']):
                    return 1.0
            elif main_category == 'doctrine':
                if any(word in document_type for word in ['tese', 'artigo', 'relatorio']):
                    return 1.0
            
            return 0.7  # Não inconsistente, mas não confirmado
            
        except Exception:
            return 0.5
    
    def _check_implementation_consistency(self, parsed_content: Dict[str, Any]) -> float:
        """Verifica consistência dos dados de implementação"""
        # Implementação simplificada - sempre retorna score médio
        return 0.8
    
    def _check_thematic_consistency(self, parsed_content: Dict[str, Any]) -> float:
        """Verifica consistência do enriquecimento temático"""
        try:
            thematic_enrichment = parsed_content.get('thematic_enrichment', {})
            primary_themes = thematic_enrichment.get('primary_themes', [])
            relevance_score = thematic_enrichment.get('relevance_score', 0)
            
            # Verifica se temas primários são consistentes com score de relevância
            if primary_themes and relevance_score > 0.5:
                return 1.0
            elif primary_themes and relevance_score > 0.3:
                return 0.8
            elif not primary_themes and relevance_score < 0.3:
                return 0.9  # Consistente, mas baixa relevância
            
            return 0.5  # Inconsistente
            
        except Exception:
            return 0.5
    
    def _check_relevance(self, parsed_content: Dict[str, Any]) -> float:
        """
        Verifica relevância para transporte de carga
        """
        relevance_indicators = []
        
        # Verificar se há temas relacionados a transporte
        thematic_relevance = self._check_thematic_relevance(parsed_content)
        relevance_indicators.append(thematic_relevance)
        
        # Verificar se há stakeholders do setor
        stakeholder_relevance = self._check_stakeholder_relevance(parsed_content)
        relevance_indicators.append(stakeholder_relevance)
        
        # Verificar se há impacto setorial identificado
        impact_relevance = self._check_impact_relevance(parsed_content)
        relevance_indicators.append(impact_relevance)
        
        return round(sum(relevance_indicators) / len(relevance_indicators), 2)
    
    def _check_thematic_relevance(self, parsed_content: Dict[str, Any]) -> float:
        """Verifica relevância temática"""
        try:
            thematic_enrichment = parsed_content.get('thematic_enrichment', {})
            primary_themes = thematic_enrichment.get('primary_themes', [])
            
            # Temas de alta relevância para transporte
            high_relevance_themes = [
                'transporte_geral', 'combustiveis_energia', 'regulamentacao_normas',
                'operacoes_servicos', 'maquinas_equipamentos'
            ]
            
            if any(theme in high_relevance_themes for theme in primary_themes):
                return 1.0
            
            # Temas de média relevância
            medium_relevance_themes = [
                'tecnologia_inovacao', 'infraestrutura', 'eficiencia_emissoes'
            ]
            
            if any(theme in medium_relevance_themes for theme in primary_themes):
                return 0.8
            
            return 0.5  # Baixa relevância temática
            
        except Exception:
            return 0.5
    
    def _check_stakeholder_relevance(self, parsed_content: Dict[str, Any]) -> float:
        """Verifica relevância dos stakeholders"""
        try:
            thematic_enrichment = parsed_content.get('thematic_enrichment', {})
            stakeholders = thematic_enrichment.get('stakeholders_identified', [])
            
            # Stakeholders de alta relevância
            high_relevance_stakeholders = [
                'transportadores', 'embarcadores', 'reguladores'
            ]
            
            if any(stakeholder in high_relevance_stakeholders for stakeholder in stakeholders):
                return 1.0
            
            if stakeholders:
                return 0.7
            
            return 0.4  # Sem stakeholders identificados
            
        except Exception:
            return 0.5
    
    def _check_impact_relevance(self, parsed_content: Dict[str, Any]) -> float:
        """Verifica relevância do impacto setorial"""
        try:
            thematic_enrichment = parsed_content.get('thematic_enrichment', {})
            sectoral_impact = thematic_enrichment.get('sectoral_impact', {})
            direct_impact = sectoral_impact.get('direct_impact', [])
            
            if direct_impact:
                return 1.0
            
            return 0.6  # Sem impacto direto identificado
            
        except Exception:
            return 0.5
    
    def _calculate_overall_quality(self, validation_results: Dict[str, Any]) -> float:
        """Calcula qualidade geral ponderada"""
        weights = {
            'completeness_score': 0.3,
            'accuracy_score': 0.3,
            'consistency_score': 0.2,
            'relevance_score': 0.2
        }
        
        weighted_score = sum(
            validation_results[metric] * weight
            for metric, weight in weights.items()
        )
        
        return round(weighted_score, 2)
    
    def _determine_quality_grade(self, overall_quality: float) -> str:
        """Determina nota de qualidade"""
        if overall_quality >= 0.9:
            return 'A+'
        elif overall_quality >= 0.8:
            return 'A'
        elif overall_quality >= 0.7:
            return 'B'
        elif overall_quality >= 0.6:
            return 'C'
        elif overall_quality >= 0.5:
            return 'D'
        else:
            return 'F'
    
    def _identify_critical_issues(self, validation_results: Dict[str, Any],
                                 parsed_content: Dict[str, Any],
                                 original_document: Dict[str, Any]) -> List[str]:
        """Identifica problemas críticos"""
        critical_issues = []
        
        # Completude muito baixa
        if validation_results['completeness_score'] < 0.4:
            critical_issues.append("Completude crítica: dados essenciais ausentes")
        
        # Precisão muito baixa
        if validation_results['accuracy_score'] < 0.4:
            critical_issues.append("Precisão crítica: dados podem estar incorretos")
        
        # Sem relevância para transporte
        if validation_results['relevance_score'] < 0.3:
            critical_issues.append("Relevância crítica: documento pode não ser sobre transporte de carga")
        
        return critical_issues
    
    def _generate_warnings(self, validation_results: Dict[str, Any],
                          parsed_content: Dict[str, Any]) -> List[str]:
        """Gera avisos baseados nos resultados"""
        warnings = []
        
        # Avisos de completude
        if validation_results['completeness_score'] < 0.7:
            warnings.append("Completude baixa: verifique se todos os campos foram extraídos")
        
        # Avisos de consistência
        if validation_results['consistency_score'] < 0.7:
            warnings.append("Consistência baixa: dados podem ser conflitantes")
        
        # Avisos de classificação
        classification = parsed_content.get('classification', {})
        if classification.get('classification_confidence', 0) < 0.7:
            warnings.append("Confiança de classificação baixa: revisar categorização")
        
        return warnings
    
    def _generate_recommendations(self, validation_results: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas nos resultados da validação"""
        recommendations = []
        
        if validation_results['completeness_score'] < 0.7:
            recommendations.append("Melhorar completude das informações extraídas")
        
        if validation_results['accuracy_score'] < 0.8:
            recommendations.append("Revisar precisão das informações extraídas")
        
        if validation_results['consistency_score'] < 0.7:
            recommendations.append("Verificar consistência interna dos dados")
        
        if validation_results['relevance_score'] < 0.6:
            recommendations.append("Focar em informações mais relevantes para transporte de carga")
        
        if validation_results['overall_quality'] < 0.6:
            recommendations.append("Considerar re-parsing do documento com prompt mais específico")
        
        return recommendations
    
    def _load_validation_rules(self) -> Dict[str, Any]:
        """Carrega regras de validação"""
        return {
            'required_fields': [
                'document_identification',
                'thematic_classification',
                'content_analysis'
            ],
            'date_formats': [
                r'\d{4}-\d{2}-\d{2}',  # ISO format
                r'\d{2}/\d{2}/\d{4}'   # Brazilian format
            ],
            'valid_document_types': [
                'Lei Ordinária', 'Lei Complementar', 'Decreto', 'Portaria',
                'Resolução', 'Medida Provisória', 'Instrução Normativa'
            ]
        }
    
    def _load_quality_thresholds(self) -> Dict[str, float]:
        """Carrega limites de qualidade"""
        return {
            'minimum_completeness': 0.5,
            'minimum_accuracy': 0.6,
            'minimum_consistency': 0.5,
            'minimum_relevance': 0.4,
            'minimum_overall': 0.5
        }