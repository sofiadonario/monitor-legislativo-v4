#!/usr/bin/env python3
"""
Sistema de Parsing Prompts para Sistema LexML
Prompts especializados por tipo de documento baseados na documentação
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from document_classifier import RefinedDocumentClassifier

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ParsedContent:
    """Estrutura para conteúdo parsed"""
    parsing_prompt_used: str
    extraction_confidence: float
    structured_data: Dict[str, Any]
    classification: Dict[str, Any]
    parsing_timestamp: str

class IntegratedParsingSystem:
    """
    Sistema integrado de parsing que seleciona o prompt adequado
    baseado na classificação refinada do documento
    """
    
    def __init__(self):
        self.classifier = RefinedDocumentClassifier()
        self.prompts = self._load_specialized_prompts()
        self.quality_controller = ParsingQualityController()
        
    def parse_document(self, document_data: Dict) -> ParsedContent:
        """
        Executa parsing completo do documento
        """
        
        # Classificação refinada
        classification = self.classifier.classify_document(
            document_data.get('urn', ''),
            document_data.get('title', ''),
            document_data.get('document_summary', ''),
            document_data.get('document_type_original', '')
        )
        
        # Seleção do prompt apropriado
        prompt = self._select_prompt(classification)
        
        # Execução do parsing
        parsed_content = self._execute_parsing(prompt, document_data)
        
        # Enriquecimento com classificação
        parsed_content['classification'] = classification
        
        # Validação de qualidade
        quality_results = self.quality_controller.validate_parsing_result(
            parsed_content, document_data
        )
        parsed_content['quality_metrics'] = quality_results
        
        return ParsedContent(
            parsing_prompt_used=prompt[:100] + "..." if len(prompt) > 100 else prompt,
            extraction_confidence=quality_results.get('overall_quality', 0.0),
            structured_data=parsed_content.get('structured_data', {}),
            classification=classification,
            parsing_timestamp=datetime.now().isoformat()
        )
    
    def _select_prompt(self, classification: Dict) -> str:
        """
        Seleciona prompt baseado na classificação
        """
        
        main_category = classification.get('main_category', 'other')
        document_type = classification.get('document_type', 'unknown')
        
        # Mapeamento de prompts específicos
        prompt_mapping = {
            ('legislation', 'lei_ordinaria'): 'legislation_lei_ordinaria',
            ('legislation', 'lei_complementar'): 'legislation_lei_ordinaria',
            ('legislation', 'decreto_presidencial'): 'legislation_decreto',
            ('legislation', 'decreto_estadual'): 'legislation_decreto',
            ('legislation', 'decreto_municipal'): 'legislation_decreto',
            ('legislation', 'portaria_ministerial'): 'legislation_portaria',
            ('legislation', 'resolucao_agencia'): 'legislation_resolucao',
            ('legislation', 'instrucao_normativa'): 'legislation_instrucao',
            ('legislation', 'medida_provisoria'): 'legislation_medida_provisoria',
            ('jurisprudence', 'stf_adi'): 'jurisprudence_stf_constitucional',
            ('jurisprudence', 'stf_adc'): 'jurisprudence_stf_constitucional',
            ('jurisprudence', 'stf_adpf'): 'jurisprudence_stf_constitucional',
            ('jurisprudence', 'stf_re'): 'jurisprudence_stf_constitucional',
            ('jurisprudence', 'stj_resp'): 'jurisprudence_stj_uniformizacao',
            ('jurisprudence', 'stj_rms'): 'jurisprudence_stj_uniformizacao',
            ('jurisprudence', 'trf_apelacao'): 'jurisprudence_trf',
            ('jurisprudence', 'trf_mandado'): 'jurisprudence_trf',
            ('jurisprudence', 'tj_apelacao'): 'jurisprudence_tj',
            ('jurisprudence', 'sumula'): 'jurisprudence_sumula',
            ('doctrine', 'tese_doutorado'): 'doctrine_tese',
            ('doctrine', 'dissertacao_mestrado'): 'doctrine_dissertacao',
            ('doctrine', 'artigo_cientifico'): 'doctrine_artigo',
            ('doctrine', 'relatorio_pesquisa'): 'doctrine_relatorio',
            ('doctrine', 'manual_tecnico'): 'doctrine_manual',
            ('doctrine', 'parecer_tecnico'): 'doctrine_parecer'
        }
        
        # Busca prompt específico
        specific_key = (main_category, document_type)
        if specific_key in prompt_mapping:
            return self.prompts[prompt_mapping[specific_key]]
        
        # Fallback para prompt geral da categoria
        general_key = f"{main_category}_geral"
        return self.prompts.get(general_key, self.prompts['default'])
    
    def _execute_parsing(self, prompt: str, document_data: Dict) -> Dict:
        """
        Executa o parsing usando o prompt selecionado
        """
        
        # Preparação do contexto
        context = self._prepare_context(document_data, prompt)
        
        # Simulação da resposta estruturada (em implementação real, seria chamada para LLM)
        parsed_result = {
            'parsing_prompt_used': prompt[:100] + "...",
            'extraction_confidence': 0.85,
            'structured_data': self._extract_structured_data(document_data, prompt)
        }
        
        return parsed_result
    
    def _prepare_context(self, document_data: Dict, prompt: str) -> str:
        """
        Prepara contexto para o parsing
        """
        
        return f"""
        DOCUMENTO PARA ANÁLISE:
        
        URN: {document_data.get('urn', 'N/A')}
        Título: {document_data.get('title', 'N/A')}
        Data: {document_data.get('enacting_date', 'N/A')}
        Tipo Original: {document_data.get('document_type_original', 'N/A')}
        Autoridade: {document_data.get('justice', 'N/A')}
        
        CONTEÚDO/EMENTA:
        {document_data.get('document_summary', 'N/A')}
        
        ---
        
        {prompt}
        """
    
    def _extract_structured_data(self, document_data: Dict, prompt: str) -> Dict:
        """
        Extrai dados estruturados baseado no prompt
        """
        
        # Estrutura básica baseada no tipo de prompt
        if 'legislation' in prompt:
            return self._extract_legislation_data(document_data)
        elif 'jurisprudence' in prompt:
            return self._extract_jurisprudence_data(document_data)
        elif 'doctrine' in prompt:
            return self._extract_doctrine_data(document_data)
        else:
            return self._extract_generic_data(document_data)
    
    def _extract_legislation_data(self, document_data: Dict) -> Dict:
        """
        Extrai dados estruturados de legislação
        """
        
        return {
            'document_identification': {
                'urn': document_data.get('urn', ''),
                'title': document_data.get('title', ''),
                'document_type': self._extract_document_type(document_data),
                'enacting_date': document_data.get('enacting_date', ''),
                'authority': document_data.get('justice', ''),
                'jurisdiction': self._extract_jurisdiction(document_data),
                'status': 'vigente'  # Padrão, seria extraído do conteúdo
            },
            'thematic_classification': {
                'primary_theme': self._extract_primary_theme(document_data),
                'secondary_themes': self._extract_secondary_themes(document_data),
                'transport_relevance': self._calculate_transport_relevance(document_data),
                'affected_sectors': self._extract_affected_sectors(document_data)
            },
            'content_analysis': {
                'objective': self._extract_objective(document_data),
                'scope': self._extract_scope(document_data),
                'main_provisions': self._extract_main_provisions(document_data),
                'implementation_timeline': self._extract_timeline(document_data)
            },
            'regulatory_impact': {
                'impact_level': self._assess_impact_level(document_data),
                'affected_stakeholders': self._identify_stakeholders(document_data),
                'compliance_requirements': self._extract_compliance_requirements(document_data),
                'economic_implications': self._extract_economic_implications(document_data)
            }
        }
    
    def _extract_jurisprudence_data(self, document_data: Dict) -> Dict:
        """
        Extrai dados estruturados de jurisprudência
        """
        
        return {
            'decision_identification': {
                'urn': document_data.get('urn', ''),
                'title': document_data.get('title', ''),
                'court': self._extract_court(document_data),
                'decision_type': self._extract_decision_type(document_data),
                'decision_date': document_data.get('enacting_date', ''),
                'case_number': self._extract_case_number(document_data)
            },
            'legal_question': {
                'central_issue': self._extract_central_issue(document_data),
                'legal_framework': self._extract_legal_framework(document_data),
                'precedents_cited': self._extract_precedents(document_data),
                'legal_principles': self._extract_legal_principles(document_data)
            },
            'decision_analysis': {
                'decision_outcome': self._extract_decision_outcome(document_data),
                'ratio_decidendi': self._extract_ratio_decidendi(document_data),
                'legal_interpretation': self._extract_legal_interpretation(document_data),
                'precedent_value': self._assess_precedent_value(document_data)
            },
            'regulatory_implications': {
                'affected_regulations': self._extract_affected_regulations(document_data),
                'industry_impact': self._assess_industry_impact(document_data),
                'compliance_guidance': self._extract_compliance_guidance(document_data)
            }
        }
    
    def _extract_doctrine_data(self, document_data: Dict) -> Dict:
        """
        Extrai dados estruturados de doutrina
        """
        
        return {
            'document_identification': {
                'urn': document_data.get('urn', ''),
                'title': document_data.get('title', ''),
                'document_type': self._extract_document_type(document_data),
                'publication_date': document_data.get('enacting_date', ''),
                'author': self._extract_author(document_data),
                'institution': self._extract_institution(document_data)
            },
            'academic_classification': {
                'knowledge_area': self._extract_knowledge_area(document_data),
                'academic_level': self._extract_academic_level(document_data),
                'research_methodology': self._extract_methodology(document_data),
                'theoretical_framework': self._extract_theoretical_framework(document_data)
            },
            'content_analysis': {
                'main_theme': self._extract_main_theme(document_data),
                'key_findings': self._extract_key_findings(document_data),
                'contributions': self._extract_contributions(document_data),
                'recommendations': self._extract_recommendations(document_data)
            },
            'regulatory_relevance': {
                'regulatory_analysis': self._extract_regulatory_analysis(document_data),
                'policy_implications': self._extract_policy_implications(document_data),
                'practical_applications': self._extract_practical_applications(document_data)
            }
        }
    
    def _extract_generic_data(self, document_data: Dict) -> Dict:
        """
        Extrai dados estruturados genéricos
        """
        
        return {
            'basic_information': {
                'urn': document_data.get('urn', ''),
                'title': document_data.get('title', ''),
                'date': document_data.get('enacting_date', ''),
                'summary': document_data.get('document_summary', ''),
                'type': document_data.get('document_type_original', '')
            },
            'content_analysis': {
                'main_topics': self._extract_main_topics(document_data),
                'transport_relevance': self._calculate_transport_relevance(document_data),
                'key_terms': self._extract_key_terms(document_data)
            }
        }
    
    # Métodos auxiliares para extração de dados específicos
    def _extract_document_type(self, document_data: Dict) -> str:
        """Extrai tipo de documento"""
        urn = document_data.get('urn', '').lower()
        if 'lei' in urn:
            return 'Lei'
        elif 'decreto' in urn:
            return 'Decreto'
        elif 'portaria' in urn:
            return 'Portaria'
        elif 'resolucao' in urn:
            return 'Resolução'
        return document_data.get('document_type_original', 'Não identificado')
    
    def _extract_jurisdiction(self, document_data: Dict) -> str:
        """Extrai jurisdição"""
        urn = document_data.get('urn', '').lower()
        if 'federal' in urn:
            return 'Federal'
        elif 'estadual' in urn:
            return 'Estadual'
        elif 'municipal' in urn:
            return 'Municipal'
        return document_data.get('court_class', 'Não identificado')
    
    def _extract_primary_theme(self, document_data: Dict) -> str:
        """Extrai tema principal"""
        summary = document_data.get('document_summary', '').lower()
        
        theme_keywords = {
            'combustíveis': ['combustível', 'diesel', 'gasolina', 'etanol', 'biometano'],
            'emissões': ['emissão', 'poluição', 'carbono', 'sustentável'],
            'segurança': ['segurança', 'acidente', 'prevenção'],
            'tributação': ['imposto', 'tributo', 'ipi', 'icms'],
            'licenciamento': ['licença', 'autorização', 'permissão'],
            'infraestrutura': ['infraestrutura', 'estrada', 'rodovia']
        }
        
        for theme, keywords in theme_keywords.items():
            if any(keyword in summary for keyword in keywords):
                return theme
        
        return 'geral'
    
    def _extract_secondary_themes(self, document_data: Dict) -> List[str]:
        """Extrai temas secundários"""
        # Implementação simplificada
        return ['transporte', 'regulamentação']
    
    def _calculate_transport_relevance(self, document_data: Dict) -> float:
        """Calcula relevância para transporte"""
        text = f"{document_data.get('title', '')} {document_data.get('document_summary', '')}".lower()
        
        transport_keywords = [
            'transporte', 'carga', 'caminhão', 'veículo', 'frete', 'logística',
            'rodoviário', 'modal', 'combustível', 'diesel', 'motorista'
        ]
        
        matches = sum(1 for keyword in transport_keywords if keyword in text)
        return min(matches / len(transport_keywords), 1.0)
    
    def _extract_affected_sectors(self, document_data: Dict) -> List[str]:
        """Identifica setores afetados"""
        summary = document_data.get('document_summary', '').lower()
        
        sectors = []
        if any(word in summary for word in ['transporte', 'logística', 'carga']):
            sectors.append('Transporte de Carga')
        if any(word in summary for word in ['combustível', 'posto', 'abastecimento']):
            sectors.append('Combustíveis')
        if any(word in summary for word in ['segurança', 'acidente', 'fiscalização']):
            sectors.append('Segurança Viária')
        
        return sectors or ['Não identificado']
    
    def _extract_objective(self, document_data: Dict) -> str:
        """Extrai objetivo do documento"""
        summary = document_data.get('document_summary', '')
        
        # Buscar por padrões que indicam objetivo
        objective_patterns = [
            r'estabelece\s+(.{1,100})',
            r'regulamenta\s+(.{1,100})',
            r'dispõe\s+sobre\s+(.{1,100})',
            r'institui\s+(.{1,100})'
        ]
        
        for pattern in objective_patterns:
            match = re.search(pattern, summary, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return summary[:200] + '...' if len(summary) > 200 else summary
    
    def _extract_scope(self, document_data: Dict) -> str:
        """Extrai escopo de aplicação"""
        summary = document_data.get('document_summary', '')
        
        if 'veículo' in summary.lower():
            return 'Veículos de transporte'
        elif 'empresa' in summary.lower():
            return 'Empresas de transporte'
        elif 'motorista' in summary.lower():
            return 'Motoristas profissionais'
        
        return 'Geral'
    
    def _extract_main_provisions(self, document_data: Dict) -> List[str]:
        """Extrai principais dispositivos"""
        # Implementação simplificada
        return ['Disposições gerais', 'Procedimentos', 'Penalidades']
    
    def _extract_timeline(self, document_data: Dict) -> str:
        """Extrai cronograma de implementação"""
        summary = document_data.get('document_summary', '')
        
        # Buscar por datas e prazos
        timeline_patterns = [
            r'(\d{1,2})\s+dias',
            r'(\d{1,2})\s+meses',
            r'(\d{1,4})\s+ano',
            r'até\s+(\d{1,2}/\d{1,2}/\d{4})'
        ]
        
        for pattern in timeline_patterns:
            match = re.search(pattern, summary, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return 'Não especificado'
    
    def _assess_impact_level(self, document_data: Dict) -> str:
        """Avalia nível de impacto"""
        summary = document_data.get('document_summary', '').lower()
        
        high_impact_keywords = ['obrigatório', 'proibido', 'multa', 'penalidade']
        medium_impact_keywords = ['deve', 'regulamenta', 'estabelece']
        
        if any(keyword in summary for keyword in high_impact_keywords):
            return 'Alto'
        elif any(keyword in summary for keyword in medium_impact_keywords):
            return 'Médio'
        else:
            return 'Baixo'
    
    def _identify_stakeholders(self, document_data: Dict) -> List[str]:
        """Identifica stakeholders afetados"""
        summary = document_data.get('document_summary', '').lower()
        
        stakeholders = []
        
        stakeholder_keywords = {
            'Transportadores': ['transportador', 'empresa de transporte', 'operador'],
            'Motoristas': ['motorista', 'condutor', 'profissional'],
            'Embarcadores': ['embarcador', 'remetente', 'cliente'],
            'Órgãos Reguladores': ['antt', 'contran', 'detran', 'governo'],
            'Fornecedores': ['fornecedor', 'fabricante', 'distribuidor']
        }
        
        for stakeholder, keywords in stakeholder_keywords.items():
            if any(keyword in summary for keyword in keywords):
                stakeholders.append(stakeholder)
        
        return stakeholders or ['Setor de transporte']
    
    def _extract_compliance_requirements(self, document_data: Dict) -> List[str]:
        """Extrai requisitos de conformidade"""
        # Implementação simplificada
        return ['Registro obrigatório', 'Documentação específica', 'Cumprimento de normas']
    
    def _extract_economic_implications(self, document_data: Dict) -> Dict:
        """Extrai implicações econômicas"""
        summary = document_data.get('document_summary', '').lower()
        
        implications = {
            'custos_estimados': 'Não especificado',
            'beneficios_esperados': 'Não especificado',
            'impacto_competitividade': 'Neutro'
        }
        
        if any(word in summary for word in ['custo', 'investimento', 'gasto']):
            implications['custos_estimados'] = 'Custos adicionais previstos'
        
        if any(word in summary for word in ['benefício', 'vantagem', 'melhoria']):
            implications['beneficios_esperados'] = 'Benefícios identificados'
        
        return implications
    
    # Métodos adicionais para jurisprudência e doutrina seguiriam padrão similar...
    
    def _load_specialized_prompts(self) -> Dict[str, str]:
        """
        Carrega todos os prompts especializados
        """
        
        return {
            'legislation_geral': """
            Você é um especialista em análise de documentos legislativos brasileiros com foco em transporte de carga. 
            Analise o documento fornecido e extraia as seguintes informações estruturadas:

            **IDENTIFICAÇÃO DO DOCUMENTO:**
            - Tipo de norma: [Lei Ordinária/Lei Complementar/Medida Provisória/Decreto/Portaria/Resolução/Instrução Normativa/Outro]
            - Número da norma: [Número oficial]
            - Data de publicação: [DD/MM/AAAA]
            - Órgão emissor: [Nome completo do órgão]
            - Esfera: [Federal/Estadual/Municipal]
            - Status: [Vigente/Revogada/Suspensa]

            **ANÁLISE DE CONTEÚDO:**
            - Objetivo principal: [Resumo em 1-2 frases]
            - Escopo de aplicação: [A quem se aplica]
            - Principais dispositivos: [Artigos ou seções mais relevantes]
            - Impacto no setor: [Alto/Médio/Baixo] - [Justificativa]
            - Prazo de implementação: [Se aplicável]

            **IMPACTO SETORIAL:**
            - Transportadores: [Impacto direto]
            - Embarcadores: [Impacto direto]
            - Fornecedores: [Impacto na cadeia]
            - Consumidores finais: [Impacto indireto]
            - Meio ambiente: [Impacto ambiental]

            Apresente a análise de forma estruturada e objetiva, priorizando informações relevantes para o monitoramento legislativo do transporte de carga.
            """,
            
            'legislation_lei_ordinaria': """
            Você é um especialista em análise de leis ordinárias brasileiras. Analise a lei fornecida com foco específico em:

            **ESTRUTURA LEGISLATIVA:**
            - Ementa: [Transcrição completa]
            - Número de artigos: [Total]
            - Divisão em capítulos/títulos: [Estrutura organizacional]
            - Disposições transitórias: [Artigos específicos]
            - Vigência: [Data de entrada em vigor]

            **CONTEÚDO NORMATIVO:**
            - Princípios estabelecidos: [Diretrizes gerais]
            - Direitos criados: [Novos direitos reconhecidos]
            - Obrigações impostas: [Deveres estabelecidos]
            - Competências definidas: [Atribuições de órgãos]
            - Instrumentos criados: [Fundos, programas, sistemas]

            **REGULAMENTAÇÃO:**
            - Dispositivos que dependem de regulamentação: [Artigos específicos]
            - Prazo para regulamentação: [Se estabelecido]
            - Órgão competente para regulamentar: [Ministério/Agência]
            - Aspectos técnicos a serem detalhados: [Especificações pendentes]

            Foque especialmente em como a lei impacta o transporte de carga e quais regulamentações complementares serão necessárias.
            """,
            
            'legislation_decreto': """
            Você é um especialista em análise de decretos do Poder Executivo. Analise o decreto fornecido considerando:

            **NATUREZA DO DECRETO:**
            - Tipo: [Regulamentar/Organizacional/Executivo/Autônomo]
            - Lei regulamentada: [Se aplicável - número e nome]
            - Competência constitucional: [Base legal para edição]
            - Hierarquia normativa: [Posição no ordenamento]

            **IMPLEMENTAÇÃO PRÁTICA:**
            - Procedimentos administrativos: [Processos detalhados]
            - Documentação necessária: [Formulários, certidões, licenças]
            - Custos envolvidos: [Taxas, emolumentos]
            - Sistemas informatizados: [Plataformas digitais]

            **FISCALIZAÇÃO E CONTROLE:**
            - Órgãos fiscalizadores: [Entidades responsáveis]
            - Instrumentos de controle: [Auditorias, inspeções]
            - Penalidades administrativas: [Multas, suspensões]
            - Recursos administrativos: [Procedimentos de defesa]

            Enfatize como o decreto operacionaliza as diretrizes legais para o setor de transporte de carga.
            """,
            
            'legislation_resolucao': """
            Você é um especialista em regulamentação setorial por agências reguladoras. Analise a resolução fornecida com foco em:

            **CONTEXTO REGULATÓRIO:**
            - Agência emissora: [ANTT/ANP/ANEEL/ANA/Outra]
            - Competência legal: [Base legal da agência]
            - Área de atuação: [Setor regulado]
            - Consulta pública: [Se houve processo participativo]

            **CONTEÚDO TÉCNICO:**
            - Normas técnicas estabelecidas: [Padrões, especificações]
            - Indicadores de qualidade: [Métricas de performance]
            - Procedimentos operacionais: [Protocolos detalhados]
            - Requisitos de segurança: [Normas de proteção]

            **IMPACTO ECONÔMICO:**
            - Custos de conformidade: [Investimentos necessários]
            - Benefícios esperados: [Eficiência, segurança, qualidade]
            - Análise de impacto regulatório: [Se disponível]
            - Prazo de adequação: [Cronograma para empresas]

            Destaque especialmente os aspectos técnicos e operacionais que impactam diretamente o transporte de carga.
            """,
            
            'jurisprudence_geral': """
            Você é um especialista em análise de jurisprudência brasileira com foco em transporte de carga. Analise a decisão judicial fornecida e extraia:

            **IDENTIFICAÇÃO DA DECISÃO:**
            - Tribunal: [STF/STJ/TRF/TJ/TST/Outro]
            - Tipo de ação: [ADI/REsp/Apelação/MS/Outro]
            - Número do processo: [Número completo]
            - Data do julgamento: [DD/MM/AAAA]
            - Relator: [Nome do magistrado]
            - Instância: [1ª/2ª/Superior/Suprema]

            **QUESTÃO JURÍDICA:**
            - Tema central: [Resumo da controvérsia]
            - Normas discutidas: [Leis, decretos, regulamentos]
            - Precedentes citados: [Jurisprudência anterior]
            - Doutrina mencionada: [Autores e obras]

            **DECISÃO:**
            - Resultado: [Procedente/Improcedente/Parcial]
            - Dispositivo: [Parte decisória]
            - Efeitos: [Imediatos/Futuros]
            - Recursos cabíveis: [Possibilidades recursais]

            **IMPACTO REGULATÓRIO:**
            - Interpretação normativa: [Como a norma foi interpretada]
            - Precedente criado: [Orientação jurisprudencial]
            - Setor afetado: [Área do transporte impactada]
            - Consequências práticas: [Mudanças necessárias]

            Foque especialmente na interpretação de normas regulatórias do transporte de carga e no impacto prático da decisão.
            """,
            
            'jurisprudence_stf_constitucional': """
            Você é um especialista em controle de constitucionalidade. Analise a decisão do STF fornecida considerando:

            **CONTROLE DE CONSTITUCIONALIDADE:**
            - Tipo de ação: [ADI/ADC/ADPF]
            - Norma impugnada: [Lei/decreto específico]
            - Vício alegado: [Formal/Material]
            - Parâmetro constitucional: [Artigos da CF/88]

            **EFEITOS DA DECISÃO:**
            - Eficácia temporal: [Ex tunc/Ex nunc]
            - Modulação de efeitos: [Se aplicável]
            - Efeito vinculante: [Órgãos vinculados]
            - Comunicação aos órgãos: [Procedimentos de comunicação]

            **IMPACTO NO TRANSPORTE:**
            - Normas afetadas: [Regulamentação específica]
            - Competência regulatória: [Definição de atribuições]
            - Segurança jurídica: [Estabilidade normativa]
            - Necessidade de nova legislação: [Lacunas criadas]

            Enfatize especialmente como a decisão afeta a competência regulatória em transporte de carga.
            """,
            
            'doctrine_geral': """
            Você é um especialista em análise de produção acadêmica e técnica sobre transporte de carga. Analise o documento doutrinário fornecido e extraia:

            **IDENTIFICAÇÃO DO DOCUMENTO:**
            - Tipo: [Tese/Dissertação/Artigo/Livro/Capítulo/Manual/Relatório/Parecer]
            - Título completo: [Transcrição exata]
            - Autor(es): [Nome completo e titulação]
            - Instituição: [Universidade/Empresa/Órgão]
            - Data de publicação: [MM/AAAA]
            - Idioma: [Português/Inglês/Espanhol/Outro]

            **CONTEÚDO TEMÁTICO:**
            - Tema principal: [Assunto central]
            - Temas secundários: [Assuntos correlatos]
            - Categoria temática: [Baseada nos novos termos de busca]
            - Escopo geográfico: [Local/Regional/Nacional/Internacional]
            - Período analisado: [Recorte temporal]

            **RESULTADOS E CONTRIBUIÇÕES:**
            - Principais achados: [Descobertas relevantes]
            - Contribuição teórica: [Avanço conceitual]
            - Contribuição prática: [Aplicação real]
            - Originalidade: [Aspectos inéditos]

            **RELEVÂNCIA REGULATÓRIA:**
            - Normas analisadas: [Legislação discutida]
            - Políticas públicas: [Programas avaliados]
            - Impacto regulatório: [Efeitos identificados]
            - Recomendações: [Sugestões de política]
            - Tendências identificadas: [Projeções futuras]

            Foque especialmente na contribuição do documento para o conhecimento sobre regulamentação do transporte de carga.
            """,
            
            'default': """
            Você é um especialista em análise de documentos relacionados ao transporte de carga no Brasil. 
            Analise o documento fornecido e extraia informações estruturadas relevantes para monitoramento legislativo, 
            focando em aspectos regulatórios, impactos setoriais e implicações práticas para o setor de transporte.
            
            Estruture sua análise de forma clara e objetiva, priorizando informações que sejam úteis para 
            profissionais e pesquisadores do setor de transporte de carga.
            """
        }


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
    
    def validate_parsing_result(self, parsed_content: Dict, original_document: Dict) -> Dict:
        """
        Valida qualidade do parsing executado
        """
        
        validation_results = {
            'completeness_score': self._check_completeness(parsed_content),
            'accuracy_score': self._check_accuracy(parsed_content, original_document),
            'consistency_score': self._check_consistency(parsed_content),
            'relevance_score': self._check_relevance(parsed_content),
            'overall_quality': 0.0,
            'recommendations': []
        }
        
        # Cálculo da qualidade geral
        scores = [v for k, v in validation_results.items() if k.endswith('_score')]
        validation_results['overall_quality'] = sum(scores) / len(scores) if scores else 0.0
        
        # Geração de recomendações
        validation_results['recommendations'] = self._generate_recommendations(validation_results)
        
        return validation_results
    
    def _check_completeness(self, parsed_content: Dict) -> float:
        """
        Verifica completude das informações extraídas
        """
        
        required_fields = [
            'structured_data'
        ]
        
        if 'structured_data' not in parsed_content:
            return 0.0
        
        structured_data = parsed_content['structured_data']
        expected_sections = ['document_identification', 'content_analysis']
        
        completed_sections = sum(
            1 for section in expected_sections 
            if section in structured_data and structured_data[section]
        )
        
        return completed_sections / len(expected_sections)
    
    def _check_accuracy(self, parsed_content: Dict, original_document: Dict) -> float:
        """
        Verifica precisão das informações extraídas
        """
        
        accuracy_checks = []
        
        # Verificar se a URN foi preservada corretamente
        if 'structured_data' in parsed_content:
            structured_data = parsed_content['structured_data']
            
            # Verificar identificação do documento
            if 'document_identification' in structured_data:
                doc_id = structured_data['document_identification']
                
                # URN deve ser preservada
                if doc_id.get('urn') == original_document.get('urn'):
                    accuracy_checks.append(1.0)
                else:
                    accuracy_checks.append(0.0)
                
                # Título deve ser preservado
                if doc_id.get('title') == original_document.get('title'):
                    accuracy_checks.append(1.0)
                else:
                    accuracy_checks.append(0.5)
        
        return sum(accuracy_checks) / len(accuracy_checks) if accuracy_checks else 0.5
    
    def _check_consistency(self, parsed_content: Dict) -> float:
        """
        Verifica consistência interna dos dados
        """
        
        if 'structured_data' not in parsed_content:
            return 0.0
        
        consistency_score = 0.8  # Score base
        
        # Verificações de consistência básicas
        structured_data = parsed_content['structured_data']
        
        # Verificar se todos os campos obrigatórios têm valores
        for section_name, section_data in structured_data.items():
            if isinstance(section_data, dict):
                empty_fields = sum(1 for v in section_data.values() if not v)
                if empty_fields > 0:
                    consistency_score -= 0.1
        
        return max(consistency_score, 0.0)
    
    def _check_relevance(self, parsed_content: Dict) -> float:
        """
        Verifica relevância das informações extraídas para transporte de carga
        """
        
        if 'structured_data' not in parsed_content:
            return 0.0
        
        structured_data = parsed_content['structured_data']
        
        # Verificar se há análise de impacto no transporte
        transport_relevance = 0.0
        
        if 'thematic_classification' in structured_data:
            thematic = structured_data['thematic_classification']
            if thematic.get('transport_relevance', 0) > 0:
                transport_relevance += 0.5
        
        if 'regulatory_impact' in structured_data:
            transport_relevance += 0.5
        
        return transport_relevance
    
    def _generate_recommendations(self, validation_results: Dict) -> List[str]:
        """
        Gera recomendações baseadas nos resultados da validação
        """
        
        recommendations = []
        
        if validation_results['completeness_score'] < 0.7:
            recommendations.append("Melhorar completude das informações extraídas")
        
        if validation_results['accuracy_score'] < 0.8:
            recommendations.append("Revisar precisão das informações extraídas")
        
        if validation_results['consistency_score'] < 0.7:
            recommendations.append("Verificar consistência interna dos dados")
        
        if validation_results['relevance_score'] < 0.6:
            recommendations.append("Focar em informações mais relevantes para transporte de carga")
        
        return recommendations


def main():
    """Função principal para teste"""
    
    # Exemplo de uso
    parsing_system = IntegratedParsingSystem()
    
    # Documento de exemplo
    test_document = {
        'urn': 'urn:lex:br:federal:lei:2021-12-29;14.267',
        'title': 'Lei sobre uso de biometano em transporte de carga',
        'document_summary': 'Estabelece diretrizes para o uso de biometano como combustível em veículos pesados de transporte de carga, visando reduzir emissões de gases de efeito estufa e promover a sustentabilidade no setor.',
        'document_type_original': 'Lei Federal',
        'enacting_date': '2021-12-29',
        'justice': 'Federal'
    }
    
    # Executar parsing
    result = parsing_system.parse_document(test_document)
    
    print("Resultado do Parsing:")
    print(f"Prompt usado: {result.parsing_prompt_used}")
    print(f"Confiança: {result.extraction_confidence}")
    print(f"Classificação: {result.classification}")
    print(f"Dados estruturados: {json.dumps(result.structured_data, indent=2, ensure_ascii=False)}")


if __name__ == "__main__":
    main()