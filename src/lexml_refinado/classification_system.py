#!/usr/bin/env python3
"""
Sistema de Classificação Refinado para LexML
Implementa classificação hierárquica em três níveis

Autor: Manus AI
Data: 2025-07-14
Versão: 2.0
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RefinedDocumentClassifier:
    """
    Sistema de classificação refinado para documentos LexML
    Implementa classificação hierárquica em três níveis
    """
    
    def __init__(self):
        self.legislation_patterns = self._load_legislation_patterns()
        self.jurisprudence_patterns = self._load_jurisprudence_patterns()
        self.doctrine_patterns = self._load_doctrine_patterns()
        
    def classify_document(self, urn: str, title: str, document_summary: str, 
                         document_type_original: str = "") -> Dict[str, any]:
        """
        Classifica documento em categoria, tipo e subtipo
        
        Args:
            urn: URN do documento
            title: Título do documento
            document_summary: Resumo/ementa do documento
            document_type_original: Tipo original do documento
            
        Returns:
            Dicionário com classificação hierárquica
        """
        # Classificação de primeiro nível (categoria principal)
        main_category = self._classify_main_category(urn, title, document_summary)
        
        # Classificação de segundo nível (tipo)
        document_type = self._classify_type(main_category, urn, title, document_summary)
        
        # Classificação de terceiro nível (subtipo)
        document_subtype = self._classify_subtype(main_category, document_type, 
                                                 urn, title, document_summary)
        
        # Cálculo de confiança
        classification_confidence = self._calculate_confidence(urn, title, document_summary)
        
        return {
            'main_category': main_category,
            'document_type': document_type,
            'document_subtype': document_subtype,
            'classification_confidence': classification_confidence
        }
    
    def _classify_main_category(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica categoria principal: legislation, jurisprudence, doctrine
        """
        urn_lower = urn.lower() if urn else ""
        
        # Padrões de legislação
        legislation_indicators = [
            'lei', 'decreto', 'portaria', 'resolucao', 'instrucao.normativa',
            'medida.provisoria', 'decreto.legislativo', 'emenda.constitucional'
        ]
        
        # Padrões de jurisprudência
        jurisprudence_indicators = [
            'jurisprudencia', 'acordao', 'decisao', 'sentenca', 'sumula',
            'recurso', 'apelacao', 'agravo', 'embargos'
        ]
        
        # Verificação por URN
        for indicator in legislation_indicators:
            if indicator in urn_lower:
                return 'legislation'
        
        for indicator in jurisprudence_indicators:
            if indicator in urn_lower:
                return 'jurisprudence'
        
        # Verificação por conteúdo textual
        text_content = f"{title} {document_summary}".lower()
        
        # Contadores de indicadores
        leg_count = sum(1 for indicator in legislation_indicators 
                       if indicator.replace('.', ' ') in text_content)
        jur_count = sum(1 for indicator in jurisprudence_indicators 
                       if indicator.replace('.', ' ') in text_content)
        
        if leg_count > jur_count and leg_count > 0:
            return 'legislation'
        elif jur_count > 0:
            return 'jurisprudence'
        else:
            return 'doctrine'
    
    def _classify_type(self, main_category: str, urn: str, title: str, 
                      document_summary: str) -> str:
        """
        Classifica tipo específico baseado na categoria principal
        """
        if main_category == 'legislation':
            return self._classify_legislation_type(urn, title, document_summary)
        elif main_category == 'jurisprudence':
            return self._classify_jurisprudence_type(urn, title, document_summary)
        elif main_category == 'doctrine':
            return self._classify_doctrine_type(urn, title, document_summary)
        else:
            return 'tipo_geral'
    
    def _classify_legislation_type(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica tipos específicos de legislação
        """
        urn_lower = urn.lower() if urn else ""
        text_content = f"{title} {document_summary}".lower()
        
        # Padrões específicos de legislação
        legislation_types = {
            'lei_ordinaria': ['lei:', 'lei.ordinaria', 'lei.federal'],
            'lei_complementar': ['lei.complementar', 'lc.'],
            'medida_provisoria': ['medida.provisoria', 'mp.', 'mp:'],
            'decreto_presidencial': ['decreto:', 'decreto.presidencial'],
            'decreto_legislativo': ['decreto.legislativo', 'decreto.do.congresso'],
            'portaria_ministerial': ['portaria:', 'portaria.ministerial'],
            'resolucao_agencia': ['resolucao:', 'resolucao.antt', 'resolucao.anp', 
                                'resolucao.aneel'],
            'instrucao_normativa': ['instrucao.normativa', 'in.'],
            'emenda_constitucional': ['emenda.constitucional', 'ec.']
        }
        
        # Verificação por URN
        for leg_type, patterns in legislation_types.items():
            for pattern in patterns:
                if pattern in urn_lower:
                    return leg_type
        
        # Verificação por conteúdo textual
        for leg_type, patterns in legislation_types.items():
            for pattern in patterns:
                if pattern.replace('.', ' ') in text_content:
                    return leg_type
        
        return 'legislacao_geral'
    
    def _classify_jurisprudence_type(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica tipos específicos de jurisprudência
        """
        urn_lower = urn.lower() if urn else ""
        text_content = f"{title} {document_summary}".lower()
        
        # Padrões específicos de jurisprudência
        jurisprudence_types = {
            'stf_adi': ['stf', 'adi', 'acao.direta.inconstitucionalidade'],
            'stf_adc': ['stf', 'adc', 'acao.declaratoria.constitucionalidade'],
            'stf_adpf': ['stf', 'adpf', 'arguicao.descumprimento.preceito'],
            'stf_re': ['stf', 're.', 'recurso.extraordinario'],
            'stj_resp': ['stj', 'resp', 'recurso.especial'],
            'stj_rms': ['stj', 'rms', 'recurso.ordinario.mandado'],
            'trf_apelacao': ['trf', 'apelacao', 'apelacao.civel'],
            'trf_mandado': ['trf', 'mandado.seguranca', 'ms.'],
            'tj_apelacao': ['tj', 'apelacao', 'tribunal.justica'],
            'tst_dissidio': ['tst', 'dissidio', 'dissidio.coletivo'],
            'sumula': ['sumula', 'sumula.vinculante']
        }
        
        # Verificação por URN e conteúdo
        for jur_type, patterns in jurisprudence_types.items():
            pattern_match = all(any(p in urn_lower for p in patterns) for p in patterns[:2]) \
                          if len(patterns) > 1 else any(p in urn_lower for p in patterns)
            if pattern_match:
                return jur_type
        
        # Verificação por conteúdo textual
        for jur_type, patterns in jurisprudence_types.items():
            pattern_match = sum(1 for p in patterns if p.replace('.', ' ') in text_content) >= 2
            if pattern_match:
                return jur_type
        
        return 'jurisprudencia_geral'
    
    def _classify_doctrine_type(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica tipos específicos de doutrina
        """
        text_content = f"{title} {document_summary}".lower()
        
        # Padrões específicos de doutrina
        doctrine_types = {
            'tese_doutorado': ['tese', 'doutorado', 'phd', 'doutor'],
            'dissertacao_mestrado': ['dissertacao', 'mestrado', 'mestre'],
            'tcc': ['tcc', 'trabalho.conclusao', 'graduacao', 'bacharelado'],
            'artigo_cientifico': ['artigo', 'paper', 'revista', 'periodico'],
            'livro': ['livro', 'obra', 'publicacao', 'editora'],
            'capitulo_livro': ['capitulo', 'cap.', 'secao'],
            'manual_tecnico': ['manual', 'guia', 'handbook', 'orientacao'],
            'relatorio_pesquisa': ['relatorio', 'estudo', 'pesquisa', 'levantamento'],
            'parecer_tecnico': ['parecer', 'opiniao', 'analise.tecnica'],
            'publicacao_associacao': ['cnt', 'antf', 'abcam', 'associacao'],
            'estudo_consultoria': ['consultoria', 'consulting', 'assessoria'],
            'relatorio_organismo': ['oecd', 'banco.mundial', 'iea', 'cepal']
        }
        
        # Verificação por conteúdo textual
        for doc_type, patterns in doctrine_types.items():
            pattern_count = sum(1 for p in patterns if p.replace('.', ' ') in text_content)
            if pattern_count >= 1:
                return doc_type
        
        # Análise de padrões estruturais
        if any(word in text_content for word in ['universidade', 'faculdade', 'instituto']):
            if 'tese' in text_content or 'doutorado' in text_content:
                return 'tese_doutorado'
            elif 'dissertacao' in text_content or 'mestrado' in text_content:
                return 'dissertacao_mestrado'
            elif 'tcc' in text_content or 'graduacao' in text_content:
                return 'tcc'
        
        return 'doutrina_geral'
    
    def _classify_subtype(self, main_category: str, document_type: str, 
                         urn: str, title: str, document_summary: str) -> str:
        """
        Classifica subtipo específico baseado na categoria e tipo
        """
        if main_category == 'legislation':
            return self._classify_legislation_subtype(document_type, urn, title, document_summary)
        elif main_category == 'jurisprudence':
            return self._classify_jurisprudence_subtype(document_type, urn, title, document_summary)
        elif main_category == 'doctrine':
            return self._classify_doctrine_subtype(document_type, urn, title, document_summary)
        
        return 'subtipo_geral'
    
    def _classify_legislation_subtype(self, document_type: str, urn: str, 
                                    title: str, document_summary: str) -> str:
        """
        Classifica subtipos de legislação baseado no conteúdo temático
        """
        text_content = f"{title} {document_summary}".lower()
        
        # Subtipos temáticos baseados nos novos termos de busca
        thematic_subtypes = {
            'combustiveis_energia': [
                'gas natural', 'biometano', 'diesel', 'biodiesel', 'hidrogenio',
                'etanol', 'combustivel', 'energia', 'renovavel'
            ],
            'eficiencia_emissoes': [
                'eficiencia energetica', 'emissoes', 'descarbonizacao',
                'gases efeito estufa', 'rotulagem veicular', 'consumo combustivel'
            ],
            'tecnologia_inovacao': [
                'tecnologias assistivas', 'veiculos autonomos', 'telemetria',
                'rastreamento', 'motorizacao', 'conversao'
            ],
            'infraestrutura': [
                'postos abastecimento', 'terminais carga', 'centros distribuicao',
                'armazens', 'infraestrutura'
            ],
            'regulamentacao_normas': [
                'contran', 'antt', 'registro', 'habilitacao', 'licenciamento',
                'rntrc', 'seguranca veicular'
            ],
            'incentivos_tributacao': [
                'ipi', 'icms', 'incentivo fiscal', 'isencao', 'beneficio tributario',
                'financiamento'
            ],
            'programas_governamentais': [
                'rota 2030', 'paten', 'transicao energetica', 'mobilidade logistica',
                'desenvolvimento sustentavel'
            ],
            'maquinas_equipamentos': [
                'maquinas agricolas', 'implementos rodoviarios', 'reboque',
                'semi-reboque', 'carreta', 'bitrem', 'rodotrem'
            ],
            'operacoes_servicos': [
                'transportador autonomo', 'empresa transporte', 'operador logistico',
                'embarcador', 'terceirizacao', 'contrato frete'
            ]
        }
        
        # Contagem de matches por subtipo
        subtype_scores = {}
        for subtype, keywords in thematic_subtypes.items():
            score = sum(1 for keyword in keywords if keyword in text_content)
            if score > 0:
                subtype_scores[subtype] = score
        
        # Retorna o subtipo com maior score
        if subtype_scores:
            return max(subtype_scores, key=subtype_scores.get)
        
        return 'legislacao_geral'
    
    def _classify_jurisprudence_subtype(self, document_type: str, urn: str, 
                                      title: str, document_summary: str) -> str:
        """
        Classifica subtipos de jurisprudência baseado no conteúdo
        """
        text_content = f"{title} {document_summary}".lower()
        
        # Análise temática similar à legislação
        if 'transporte' in text_content:
            if 'tributario' in text_content or 'icms' in text_content:
                return 'jurisprudencia_tributaria'
            elif 'ambiental' in text_content or 'licenciamento' in text_content:
                return 'jurisprudencia_ambiental'
            elif 'trabalhista' in text_content or 'motorista' in text_content:
                return 'jurisprudencia_trabalhista'
            else:
                return 'jurisprudencia_transporte'
        
        return 'jurisprudencia_geral'
    
    def _classify_doctrine_subtype(self, document_type: str, urn: str, 
                                  title: str, document_summary: str) -> str:
        """
        Classifica subtipos de doutrina baseado no conteúdo
        """
        text_content = f"{title} {document_summary}".lower()
        
        # Análise de foco temático
        if 'regulacao' in text_content or 'regulamentacao' in text_content:
            return 'doutrina_regulatoria'
        elif 'economico' in text_content or 'mercado' in text_content:
            return 'doutrina_economica'
        elif 'ambiental' in text_content or 'sustentabilidade' in text_content:
            return 'doutrina_ambiental'
        elif 'tecnologia' in text_content or 'inovacao' in text_content:
            return 'doutrina_tecnologica'
        
        return 'doutrina_geral'
    
    def _calculate_confidence(self, urn: str, title: str, document_summary: str) -> float:
        """
        Calcula confiança da classificação baseada na qualidade dos indicadores
        """
        confidence_factors = {
            'urn_clarity': 0.4,  # Clareza da URN
            'title_relevance': 0.3,  # Relevância do título
            'content_indicators': 0.3  # Indicadores no conteúdo
        }
        
        # Avaliação da clareza da URN
        urn_score = 1.0 if urn and any(indicator in urn.lower() for indicator in 
                                      ['lei', 'decreto', 'portaria', 'resolucao', 
                                       'jurisprudencia']) else 0.5
        
        # Avaliação da relevância do título
        title_score = 1.0 if title and len(title) > 20 and any(word in title.lower() 
                            for word in ['transporte', 'carga', 'veiculo', 
                                       'combustivel']) else 0.7
        
        # Avaliação dos indicadores de conteúdo
        content_score = 1.0 if document_summary and len(document_summary) > 50 else 0.6
        
        # Cálculo da confiança ponderada
        confidence = (
            urn_score * confidence_factors['urn_clarity'] +
            title_score * confidence_factors['title_relevance'] +
            content_score * confidence_factors['content_indicators']
        )
        
        return round(confidence, 2)
    
    def _load_legislation_patterns(self) -> Dict[str, List[str]]:
        """Carrega padrões de legislação"""
        return {
            'federal': ['federal', 'uniao', 'nacional'],
            'estadual': ['estadual', 'estado'],
            'municipal': ['municipal', 'municipio', 'prefeitura']
        }
    
    def _load_jurisprudence_patterns(self) -> Dict[str, List[str]]:
        """Carrega padrões de jurisprudência"""
        return {
            'tribunais_superiores': ['stf', 'stj', 'tst', 'superior'],
            'tribunais_federais': ['trf', 'federal'],
            'tribunais_estaduais': ['tj', 'tjsp', 'tjrj', 'tjmg']
        }
    
    def _load_doctrine_patterns(self) -> Dict[str, List[str]]:
        """Carrega padrões de doutrina"""
        return {
            'academico': ['universidade', 'faculdade', 'instituto', 'pesquisa'],
            'institucional': ['relatorio', 'estudo', 'parecer'],
            'setorial': ['associacao', 'sindicato', 'federacao']
        }