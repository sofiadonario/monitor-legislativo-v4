#!/usr/bin/env python3
"""
Sistema de Parsing Prompts Especializados para LexML
Implementa prompts refinados por tipo de documento

Autor: Manus AI
Data: 2025-07-14
Versão: 2.0
"""

import logging
from typing import Dict, List, Optional, Any
from .classification_system import RefinedDocumentClassifier

logger = logging.getLogger(__name__)


class IntegratedParsingSystem:
    """
    Sistema integrado de parsing que seleciona o prompt adequado
    baseado na classificação refinada do documento
    """
    
    def __init__(self):
        self.classifier = RefinedDocumentClassifier()
        self.prompts = self._load_specialized_prompts()
        
    def parse_document(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa parsing completo do documento
        
        Args:
            document_data: Dados do documento incluindo urn, title, summary, etc.
            
        Returns:
            Conteúdo parseado com classificação e dados estruturados
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
        
        return parsed_content
    
    def _select_prompt(self, classification: Dict[str, str]) -> str:
        """
        Seleciona prompt baseado na classificação
        """
        main_category = classification['main_category']
        document_type = classification['document_type']
        
        # Mapeamento de prompts específicos
        prompt_mapping = {
            ('legislation', 'lei_ordinaria'): 'legislation_lei_ordinaria',
            ('legislation', 'decreto_presidencial'): 'legislation_decreto',
            ('legislation', 'resolucao_agencia'): 'legislation_resolucao',
            ('jurisprudence', 'stf_adi'): 'jurisprudence_stf_constitucional',
            ('jurisprudence', 'stj_resp'): 'jurisprudence_stj_uniformizacao',
            ('doctrine', 'tese_doutorado'): 'doctrine_tese',
            ('doctrine', 'artigo_cientifico'): 'doctrine_artigo',
            ('doctrine', 'relatorio_pesquisa'): 'doctrine_relatorio'
        }
        
        # Busca prompt específico
        specific_key = (main_category, document_type)
        if specific_key in prompt_mapping:
            return self.prompts[prompt_mapping[specific_key]]
        
        # Fallback para prompt geral da categoria
        general_key = f"{main_category}_geral"
        return self.prompts.get(general_key, self.prompts['default'])
    
    def _execute_parsing(self, prompt: str, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa o parsing usando o prompt selecionado
        
        Nota: Esta é uma implementação base. Em produção, integraria com LLM.
        """
        # Preparação do contexto
        context = f"""
        DOCUMENTO PARA ANÁLISE:
        
        URN: {document_data.get('urn', 'N/A')}
        Título: {document_data.get('title', 'N/A')}
        Data: {document_data.get('enacting_date', 'N/A')}
        Tipo Original: {document_data.get('document_type_original', 'N/A')}
        
        CONTEÚDO/EMENTA:
        {document_data.get('document_summary', 'N/A')}
        
        ---
        
        {prompt}
        """
        
        # Simulação da resposta estruturada
        # Em produção, aqui seria feita a chamada para o modelo de linguagem
        parsed_result = {
            'parsing_prompt_used': prompt[:100] + "...",
            'extraction_confidence': 0.85,
            'structured_data': {
                'document_identification': self._extract_identification(document_data),
                'thematic_classification': self._extract_themes(document_data),
                'content_analysis': self._extract_content_analysis(document_data),
                'regulatory_impact': self._extract_regulatory_impact(document_data),
                'implementation_details': self._extract_implementation(document_data)
            }
        }
        
        return parsed_result
    
    def _extract_identification(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai informações de identificação do documento"""
        return {
            'tipo_norma': document_data.get('document_type_full', ''),
            'numero_norma': self._extract_document_number(document_data.get('title', '')),
            'data_publicacao': document_data.get('enacting_date', ''),
            'orgao_emissor': self._extract_issuing_body(document_data.get('title', '')),
            'esfera': document_data.get('region', ''),
            'status': 'Vigente'  # Padrão, poderia ser extraído do conteúdo
        }
    
    def _extract_themes(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai classificação temática do documento"""
        text_content = f"{document_data.get('title', '')} {document_data.get('document_summary', '')}".lower()
        
        themes = []
        theme_keywords = {
            'Combustíveis e Energia': ['combustível', 'energia', 'diesel', 'biodiesel', 'gás natural'],
            'Eficiência Energética e Emissões': ['eficiência', 'emissões', 'descarbonização'],
            'Tecnologia e Inovação': ['tecnologia', 'inovação', 'telemetria', 'rastreamento'],
            'Infraestrutura': ['infraestrutura', 'terminal', 'posto', 'abastecimento'],
            'Regulamentação e Normas': ['regulamentação', 'norma', 'licenciamento', 'registro'],
            'Incentivos e Tributação': ['incentivo', 'isenção', 'icms', 'ipi', 'tributo'],
            'Programas Governamentais': ['programa', 'rota 2030', 'paten'],
            'Máquinas e Equipamentos': ['máquina', 'equipamento', 'reboque', 'carreta'],
            'Operações e Serviços': ['transporte', 'frete', 'logística', 'operador'],
            'Transporte Geral': ['transporte', 'carga', 'caminhão', 'veículo']
        }
        
        for theme, keywords in theme_keywords.items():
            if any(keyword in text_content for keyword in keywords):
                themes.append(theme)
        
        return {
            'categoria_principal': themes[0] if themes else 'Transporte Geral',
            'categorias_secundarias': themes[1:] if len(themes) > 1 else []
        }
    
    def _extract_content_analysis(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai análise de conteúdo do documento"""
        return {
            'objetivo_principal': self._extract_objective(document_data.get('document_summary', '')),
            'escopo_aplicacao': 'Transportadores de carga em território nacional',
            'principais_dispositivos': [],
            'impacto_setor': 'Médio',
            'prazo_implementacao': 'Não especificado'
        }
    
    def _extract_regulatory_impact(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai impacto regulatório do documento"""
        return {
            'normas_revogadas': [],
            'normas_alteradas': [],
            'regulamentacao_necessaria': [],
            'compatibilidade_normas': 'A ser avaliada'
        }
    
    def _extract_implementation(self, document_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai detalhes de implementação"""
        return {
            'orgaos_responsaveis': [],
            'recursos_necessarios': 'A ser definido',
            'cronograma': 'Não especificado',
            'indicadores_acompanhamento': []
        }
    
    def _extract_document_number(self, title: str) -> str:
        """Extrai número do documento do título"""
        import re
        # Padrões comuns de numeração
        patterns = [
            r'n[º°]\s*(\d+(?:\.\d+)*)',
            r'(\d+(?:\.\d+)*)/(\d{4})',
            r'(\d+),?\s*de\s*\d+\s*de'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'S/N'
    
    def _extract_issuing_body(self, title: str) -> str:
        """Extrai órgão emissor do título"""
        # Lista de órgãos comuns
        organs = [
            'ANTT', 'ANP', 'ANEEL', 'ANA', 'CONTRAN', 'DENATRAN',
            'Ministério', 'Secretaria', 'Agência', 'Conselho'
        ]
        
        title_upper = title.upper()
        for organ in organs:
            if organ.upper() in title_upper:
                return organ
        
        return 'Órgão não identificado'
    
    def _extract_objective(self, summary: str) -> str:
        """Extrai objetivo principal do resumo"""
        if not summary:
            return 'Objetivo não especificado'
        
        # Pega as primeiras 150 caracteres ou primeira frase
        first_sentence = summary.split('.')[0] if '.' in summary else summary[:150]
        return first_sentence.strip()
    
    def _load_specialized_prompts(self) -> Dict[str, str]:
        """
        Carrega todos os prompts especializados
        """
        return {
            'legislation_geral': self._get_legislation_general_prompt(),
            'legislation_lei_ordinaria': self._get_lei_ordinaria_prompt(),
            'legislation_decreto': self._get_decreto_prompt(),
            'legislation_resolucao': self._get_resolucao_prompt(),
            'jurisprudence_geral': self._get_jurisprudence_general_prompt(),
            'jurisprudence_stf_constitucional': self._get_stf_constitutional_prompt(),
            'jurisprudence_stj_uniformizacao': self._get_stj_uniformization_prompt(),
            'doctrine_geral': self._get_doctrine_general_prompt(),
            'doctrine_tese': self._get_tese_doutorado_prompt(),
            'doctrine_artigo': self._get_artigo_cientifico_prompt(),
            'doctrine_relatorio': self._get_relatorio_tecnico_prompt(),
            'default': self._get_default_prompt()
        }
    
    def _get_legislation_general_prompt(self) -> str:
        """Prompt geral para documentos legislativos"""
        return """
Você é um especialista em análise de documentos legislativos brasileiros com foco em transporte de carga. 
Analise o documento fornecido e extraia as seguintes informações estruturadas:

**IDENTIFICAÇÃO DO DOCUMENTO:**
- Tipo de norma: [Lei Ordinária/Lei Complementar/Medida Provisória/Decreto/Portaria/Resolução/Instrução Normativa/Outro]
- Número da norma: [Número oficial]
- Data de publicação: [DD/MM/AAAA]
- Órgão emissor: [Nome completo do órgão]
- Esfera: [Federal/Estadual/Municipal]
- Status: [Vigente/Revogada/Suspensa]

**CLASSIFICAÇÃO TEMÁTICA:**
Identifique a categoria temática principal baseada nos novos termos de busca:
- Combustíveis e Energia
- Eficiência Energética e Emissões  
- Tecnologia e Inovação
- Infraestrutura
- Regulamentação e Normas
- Incentivos e Tributação
- Programas Governamentais
- Máquinas e Equipamentos
- Operações e Serviços
- Transporte Geral

**ANÁLISE DE CONTEÚDO:**
- Objetivo principal: [Resumo em 1-2 frases]
- Escopo de aplicação: [A quem se aplica]
- Principais dispositivos: [Artigos ou seções mais relevantes]
- Impacto no setor: [Alto/Médio/Baixo] - [Justificativa]
- Prazo de implementação: [Se aplicável]

**ASPECTOS TÉCNICOS:**
- Definições importantes: [Termos técnicos definidos]
- Requisitos técnicos: [Especificações, padrões, limites]
- Procedimentos estabelecidos: [Processos, autorizações, licenças]
- Penalidades: [Multas, sanções, suspensões]

**RELAÇÕES NORMATIVAS:**
- Normas revogadas: [Se aplicável]
- Normas alteradas: [Se aplicável]
- Normas regulamentadoras necessárias: [Se aplicável]
- Compatibilidade com normas existentes: [Análise de conflitos]

**IMPLEMENTAÇÃO:**
- Órgãos responsáveis: [Entidades encarregadas da implementação]
- Recursos necessários: [Orçamentários, humanos, técnicos]
- Cronograma: [Fases de implementação]
- Indicadores de acompanhamento: [Métricas de sucesso]

**IMPACTO SETORIAL:**
- Transportadores: [Impacto direto]
- Embarcadores: [Impacto direto]
- Fornecedores: [Impacto na cadeia]
- Consumidores finais: [Impacto indireto]
- Meio ambiente: [Impacto ambiental]

Apresente a análise de forma estruturada e objetiva, priorizando informações relevantes para o monitoramento legislativo do transporte de carga.
"""
    
    def _get_lei_ordinaria_prompt(self) -> str:
        """Prompt específico para Leis Ordinárias"""
        return """
Você é um especialista em análise de leis ordinárias brasileiras. Analise a lei fornecida com foco específico em:

**ESTRUTURA LEGISLATIVA:**
- Ementa: [Transcrição completa]
- Número de artigos: [Total]
- Divisão em capítulos/títulos: [Estrutura organizacional]
- Disposições transitórias: [Artigos específicos]
- Vigência: [Data de entrada em vigor]

**PROCESSO LEGISLATIVO:**
- Origem: [Poder Executivo/Legislativo/Iniciativa Popular]
- Tramitação: [Câmara/Senado/Sanção]
- Vetos: [Dispositivos vetados, se aplicável]
- Alterações durante tramitação: [Emendas relevantes]

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
"""
    
    def _get_decreto_prompt(self) -> str:
        """Prompt específico para Decretos"""
        return """
Você é um especialista em análise de decretos do Poder Executivo. Analise o decreto fornecido considerando:

**NATUREZA DO DECRETO:**
- Tipo: [Regulamentar/Organizacional/Executivo/Autônomo]
- Lei regulamentada: [Se aplicável - número e nome]
- Competência constitucional: [Base legal para edição]
- Hierarquia normativa: [Posição no ordenamento]

**CONTEÚDO REGULAMENTAR:**
- Aspectos da lei regulamentados: [Dispositivos específicos]
- Detalhamento técnico: [Especificações, padrões, procedimentos]
- Prazos estabelecidos: [Cronogramas, deadlines]
- Responsabilidades atribuídas: [Órgãos e suas competências]

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
"""
    
    def _get_resolucao_prompt(self) -> str:
        """Prompt específico para Resoluções de Agências"""
        return """
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

**MONITORAMENTO:**
- Indicadores de acompanhamento: [Métricas de controle]
- Relatórios obrigatórios: [Informações a serem prestadas]
- Revisões periódicas: [Cronograma de atualização]
- Penalidades por descumprimento: [Sanções aplicáveis]

Destaque especialmente os aspectos técnicos e operacionais que impactam diretamente o transporte de carga.
"""
    
    def _get_jurisprudence_general_prompt(self) -> str:
        """Prompt geral para decisões judiciais"""
        return """
Você é um especialista em análise de jurisprudência brasileira com foco em transporte de carga. 
Analise a decisão judicial fornecida e extraia:

**IDENTIFICAÇÃO DA DECISÃO:**
- Tribunal: [STF/STJ/TRF/TJ/TST/Outro]
- Tipo de ação: [ADI/REsp/Apelação/MS/Outro]
- Número do processo: [Número completo]
- Data do julgamento: [DD/MM/AAAA]
- Relator: [Nome do magistrado]
- Instância: [1ª/2ª/Superior/Suprema]

**PARTES ENVOLVIDAS:**
- Requerente/Autor: [Identificação]
- Requerido/Réu: [Identificação]
- Terceiros interessados: [Se aplicável]
- Tipo de parte: [Pessoa física/jurídica/ente público]

**QUESTÃO JURÍDICA:**
- Tema central: [Resumo da controvérsia]
- Normas discutidas: [Leis, decretos, regulamentos]
- Precedentes citados: [Jurisprudência anterior]
- Doutrina mencionada: [Autores e obras]

**FUNDAMENTAÇÃO:**
- Argumentos do autor: [Teses principais]
- Argumentos da defesa: [Contrapontos]
- Posição do Ministério Público: [Se aplicável]
- Fundamentos da decisão: [Ratio decidendi]

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

**RELEVÂNCIA:**
- Repercussão geral: [Se aplicável - STF]
- Recurso repetitivo: [Se aplicável - STJ]
- Súmula: [Se gerou ou confirmou súmula]
- Abrangência: [Local/Regional/Nacional]

Foque especialmente na interpretação de normas regulatórias do transporte de carga e no impacto prático da decisão.
"""
    
    def _get_stf_constitutional_prompt(self) -> str:
        """Prompt específico para STF (Controle de Constitucionalidade)"""
        return """
Você é um especialista em controle de constitucionalidade. Analise a decisão do STF fornecida considerando:

**CONTROLE DE CONSTITUCIONALIDADE:**
- Tipo de ação: [ADI/ADC/ADPF]
- Norma impugnada: [Lei/decreto específico]
- Vício alegado: [Formal/Material]
- Parâmetro constitucional: [Artigos da CF/88]

**LEGITIMIDADE:**
- Requerente: [Legitimado ativo]
- Pertinência temática: [Se aplicável]
- Interesse de agir: [Justificativa]
- Representatividade: [Adequação do polo ativo]

**MÉRITO CONSTITUCIONAL:**
- Princípios constitucionais: [Envolvidos na discussão]
- Competências federativas: [União/Estados/Municípios]
- Direitos fundamentais: [Se aplicáveis]
- Ordem econômica: [Aspectos econômicos constitucionais]

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
"""
    
    def _get_stj_uniformization_prompt(self) -> str:
        """Prompt específico para STJ (Uniformização de Jurisprudência)"""
        return """
Você é um especialista em direito administrativo e regulatório. Analise a decisão do STJ fornecida focando em:

**RECURSO ESPECIAL:**
- Fundamento: [Violação de lei federal/Divergência]
- Lei federal discutida: [Norma específica]
- Acórdão recorrido: [Tribunal de origem]
- Divergência jurisprudencial: [Se aplicável]

**QUESTÃO FEDERAL:**
- Interpretação de lei federal: [Dispositivo específico]
- Aplicação da norma: [Caso concreto]
- Conflito normativo: [Se existente]
- Lacuna legal: [Se identificada]

**PRECEDENTES:**
- Jurisprudência consolidada: [Posição do STJ]
- Súmulas aplicáveis: [Enunciados relevantes]
- Recursos repetitivos: [Temas afetados]
- Mudança de orientação: [Se houve]

**DIREITO ADMINISTRATIVO:**
- Ato administrativo: [Legalidade/Legitimidade]
- Processo administrativo: [Due process]
- Discricionariedade: [Limites e controle]
- Responsabilidade do Estado: [Se aplicável]

**UNIFORMIZAÇÃO:**
- Tese jurídica: [Orientação estabelecida]
- Aplicação a casos similares: [Extensão da decisão]
- Segurança jurídica: [Previsibilidade]
- Orientação aos tribunais: [Diretrizes]

Destaque como a decisão uniformiza a interpretação de normas regulatórias do transporte.
"""
    
    def _get_doctrine_general_prompt(self) -> str:
        """Prompt geral para documentos doutrinários"""
        return """
Você é um especialista em análise de produção acadêmica e técnica sobre transporte de carga. 
Analise o documento doutrinário fornecido e extraia:

**IDENTIFICAÇÃO DO DOCUMENTO:**
- Tipo: [Tese/Dissertação/Artigo/Livro/Capítulo/Manual/Relatório/Parecer]
- Título completo: [Transcrição exata]
- Autor(es): [Nome completo e titulação]
- Instituição: [Universidade/Empresa/Órgão]
- Data de publicação: [MM/AAAA]
- Idioma: [Português/Inglês/Espanhol/Outro]

**CLASSIFICAÇÃO ACADÊMICA:**
- Área do conhecimento: [Direito/Engenharia/Economia/Administração/Outro]
- Subárea: [Especialização específica]
- Nível acadêmico: [Graduação/Mestrado/Doutorado/Pós-doc]
- Orientador: [Se aplicável]
- Programa de pós-graduação: [Se aplicável]

**CONTEÚDO TEMÁTICO:**
- Tema principal: [Assunto central]
- Temas secundários: [Assuntos correlatos]
- Categoria temática: [Baseada nos novos termos de busca]
- Escopo geográfico: [Local/Regional/Nacional/Internacional]
- Período analisado: [Recorte temporal]

**METODOLOGIA:**
- Tipo de pesquisa: [Qualitativa/Quantitativa/Mista]
- Método: [Estudo de caso/Survey/Experimental/Revisão]
- Fontes de dados: [Primárias/Secundárias]
- Técnicas de análise: [Estatística/Documental/Entrevistas]
- Limitações: [Restrições metodológicas]

**MARCO TEÓRICO:**
- Teorias utilizadas: [Principais referenciais]
- Autores principais: [Referências centrais]
- Conceitos-chave: [Definições importantes]
- Estado da arte: [Conhecimento existente]
- Lacunas identificadas: [Gaps de conhecimento]

**RESULTADOS E CONTRIBUIÇÕES:**
- Principais achados: [Descobertas relevantes]
- Contribuição teórica: [Avanço conceitual]
- Contribuição prática: [Aplicação real]
- Contribuição metodológica: [Inovação em métodos]
- Originalidade: [Aspectos inéditos]

**RELEVÂNCIA REGULATÓRIA:**
- Normas analisadas: [Legislação discutida]
- Políticas públicas: [Programas avaliados]
- Impacto regulatório: [Efeitos identificados]
- Recomendações: [Sugestões de política]
- Tendências identificadas: [Projeções futuras]

**QUALIDADE ACADÊMICA:**
- Rigor metodológico: [Alto/Médio/Baixo]
- Relevância dos dados: [Atualidade e pertinência]
- Consistência teórica: [Coerência conceitual]
- Aplicabilidade: [Utilidade prática]
- Impacto potencial: [Influência esperada]

Foque especialmente na contribuição do documento para o conhecimento sobre regulamentação do transporte de carga.
"""
    
    def _get_tese_doutorado_prompt(self) -> str:
        """Prompt específico para Teses de Doutorado"""
        return """
Você é um especialista em análise de teses de doutorado. Analise a tese fornecida com foco específico em:

**ESTRUTURA ACADÊMICA:**
- Programa de doutorado: [Nome completo]
- Universidade: [Instituição]
- Área de concentração: [Especialização]
- Linha de pesquisa: [Foco específico]
- Orientador: [Nome e titulação]
- Coorientador: [Se aplicável]
- Banca examinadora: [Composição]

**PROBLEMA DE PESQUISA:**
- Questão central: [Problema investigado]
- Hipóteses: [Proposições testadas]
- Objetivos: [Geral e específicos]
- Justificativa: [Relevância da pesquisa]
- Delimitação: [Escopo e limites]

**REVISÃO DE LITERATURA:**
- Estado da arte: [Conhecimento existente]
- Lacunas identificadas: [Gaps teóricos]
- Posicionamento teórico: [Escola de pensamento]
- Contribuição esperada: [Avanço proposto]
- Referencial internacional: [Comparações globais]

**METODOLOGIA AVANÇADA:**
- Paradigma de pesquisa: [Positivista/Interpretativista/Crítico]
- Estratégia de pesquisa: [Abordagem geral]
- Desenho de pesquisa: [Estrutura metodológica]
- Coleta de dados: [Técnicas utilizadas]
- Análise de dados: [Métodos analíticos]
- Validação: [Critérios de qualidade]

**CONTRIBUIÇÕES ORIGINAIS:**
- Contribuição teórica: [Avanço conceitual]
- Contribuição empírica: [Evidências inéditas]
- Contribuição metodológica: [Inovação em métodos]
- Contribuição prática: [Aplicações reais]
- Ineditismo: [Aspectos originais]

**IMPACTO ACADÊMICO:**
- Citações recebidas: [Se disponível]
- Publicações derivadas: [Artigos gerados]
- Prêmios recebidos: [Reconhecimentos]
- Aplicação prática: [Uso real dos resultados]
- Influência na área: [Impacto no campo]

Enfatize especialmente a originalidade e contribuição da tese para o conhecimento sobre transporte de carga.
"""
    
    def _get_artigo_cientifico_prompt(self) -> str:
        """Prompt específico para Artigos Científicos"""
        return """
Você é um especialista em análise de produção científica. Analise o artigo fornecido considerando:

**PUBLICAÇÃO:**
- Periódico: [Nome da revista]
- ISSN: [Se disponível]
- Volume/Número: [Identificação]
- Páginas: [Intervalo]
- DOI: [Se disponível]
- Qualis/JCR: [Classificação, se conhecida]
- Indexação: [Bases de dados]

**ESTRUTURA DO ARTIGO:**
- Resumo: [Síntese do conteúdo]
- Palavras-chave: [Termos indexadores]
- Introdução: [Contextualização]
- Metodologia: [Abordagem utilizada]
- Resultados: [Principais achados]
- Discussão: [Interpretação dos resultados]
- Conclusões: [Síntese final]

**RIGOR CIENTÍFICO:**
- Revisão por pares: [Se aplicável]
- Metodologia adequada: [Coerência metodológica]
- Dados confiáveis: [Qualidade das fontes]
- Análise consistente: [Lógica analítica]
- Conclusões suportadas: [Evidências suficientes]

**RELEVÂNCIA:**
- Atualidade: [Contemporaneidade do tema]
- Aplicabilidade: [Utilidade prática]
- Inovação: [Aspectos inéditos]
- Impacto potencial: [Influência esperada]
- Alinhamento com tendências: [Relevância futura]

**CITAÇÕES E REFERÊNCIAS:**
- Referências principais: [Autores centrais]
- Atualidade das fontes: [Contemporaneidade]
- Diversidade de fontes: [Variedade de referências]
- Qualidade das referências: [Relevância das fontes]
- Autocitação: [Proporção adequada]

Destaque especialmente a contribuição do artigo para o conhecimento científico sobre transporte de carga.
"""
    
    def _get_relatorio_tecnico_prompt(self) -> str:
        """Prompt específico para Relatórios Técnicos"""
        return """
Você é um especialista em análise de relatórios técnicos e estudos setoriais. Analise o relatório fornecido focando em:

**IDENTIFICAÇÃO INSTITUCIONAL:**
- Instituição responsável: [Órgão/Empresa/Consultoria]
- Tipo de instituição: [Pública/Privada/Mista/Internacional]
- Equipe técnica: [Responsáveis pelo estudo]
- Contratante: [Se aplicável]
- Finalidade: [Objetivo do relatório]

**ESCOPO DO ESTUDO:**
- Objeto de análise: [Tema específico]
- Abrangência geográfica: [Área coberta]
- Período analisado: [Recorte temporal]
- Setores envolvidos: [Segmentos estudados]
- Stakeholders: [Partes interessadas]

**METODOLOGIA TÉCNICA:**
- Abordagem metodológica: [Quantitativa/Qualitativa]
- Fontes de informação: [Dados utilizados]
- Técnicas de coleta: [Métodos de obtenção]
- Ferramentas de análise: [Instrumentos analíticos]
- Validação dos dados: [Controle de qualidade]

**DIAGNÓSTICO:**
- Situação atual: [Estado presente]
- Problemas identificados: [Gargalos e desafios]
- Oportunidades: [Potenciais de melhoria]
- Tendências: [Projeções futuras]
- Benchmarking: [Comparações relevantes]

**RECOMENDAÇÕES:**
- Propostas de ação: [Medidas sugeridas]
- Priorização: [Ordem de importância]
- Cronograma: [Prazos sugeridos]
- Recursos necessários: [Investimentos requeridos]
- Responsabilidades: [Atores envolvidos]

**IMPACTO REGULATÓRIO:**
- Normas relacionadas: [Regulamentação pertinente]
- Necessidades regulatórias: [Lacunas identificadas]
- Propostas normativas: [Sugestões de regulamentação]
- Impacto de políticas: [Efeitos de medidas existentes]
- Recomendações regulatórias: [Sugestões normativas]

Enfatize especialmente as recomendações técnicas que podem influenciar a regulamentação do transporte de carga.
"""
    
    def _get_default_prompt(self) -> str:
        """Prompt padrão para casos não classificados"""
        return """
Analise o documento fornecido e extraia informações relevantes para o monitoramento legislativo 
e regulatório do transporte de carga. Identifique:

1. Tipo e natureza do documento
2. Principais temas abordados
3. Relevância para o setor de transporte
4. Impactos potenciais
5. Recomendações ou diretrizes apresentadas

Forneça uma análise estruturada e objetiva.
"""