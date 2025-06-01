# Parsing Prompts Refinados para Sistema LexML
## Prompts Especializados por Tipo de Documento

**Autor:** Manus AI  
**Data:** 2025-07-12  
**Versão:** 2.0 - Sistema Refinado  

---

## 1. Parsing Prompt para Legislação

### 1.1 Prompt Geral para Documentos Legislativos

```
Você é um especialista em análise de documentos legislativos brasileiros com foco em transporte de carga. Analise o documento fornecido e extraia as seguintes informações estruturadas:

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
```

### 1.2 Prompt Específico para Leis Ordinárias

```
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
```

### 1.3 Prompt Específico para Decretos

```
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
```

### 1.4 Prompt Específico para Resoluções de Agências

```
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
```

---

## 2. Parsing Prompt para Jurisprudência

### 2.1 Prompt Geral para Decisões Judiciais

```
Você é um especialista em análise de jurisprudência brasileira com foco em transporte de carga. Analise a decisão judicial fornecida e extraia:

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
```

### 2.2 Prompt Específico para STF (Controle de Constitucionalidade)

```
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
```

### 2.3 Prompt Específico para STJ (Uniformização de Jurisprudência)

```
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
```

---

## 3. Parsing Prompt para Doutrina

### 3.1 Prompt Geral para Documentos Doutrinários

```
Você é um especialista em análise de produção acadêmica e técnica sobre transporte de carga. Analise o documento doutrinário fornecido e extraia:

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
```

### 3.2 Prompt Específico para Teses de Doutorado

```
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
```

### 3.3 Prompt Específico para Artigos Científicos

```
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
```

### 3.4 Prompt Específico para Relatórios Técnicos

```
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
```

---

## 4. Sistema Integrado de Parsing

### 4.1 Orquestrador de Parsing Prompts

```python
class IntegratedParsingSystem:
    """
    Sistema integrado de parsing que seleciona o prompt adequado
    baseado na classificação refinada do documento
    """
    
    def __init__(self):
        self.classifier = RefinedDocumentClassifier()
        self.prompts = self._load_specialized_prompts()
        
    def parse_document(self, document_data):
        """
        Executa parsing completo do documento
        """
        
        # Classificação refinada
        classification = self.classifier.classify_document(
            document_data['urn'],
            document_data['title'],
            document_data['document_summary'],
            document_data.get('document_type_original', '')
        )
        
        # Seleção do prompt apropriado
        prompt = self._select_prompt(classification)
        
        # Execução do parsing
        parsed_content = self._execute_parsing(prompt, document_data)
        
        # Enriquecimento com classificação
        parsed_content['classification'] = classification
        
        return parsed_content
    
    def _select_prompt(self, classification):
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
    
    def _execute_parsing(self, prompt, document_data):
        """
        Executa o parsing usando o prompt selecionado
        """
        
        # Preparação do contexto
        context = f"""
        DOCUMENTO PARA ANÁLISE:
        
        URN: {document_data['urn']}
        Título: {document_data['title']}
        Data: {document_data.get('enacting_date', 'N/A')}
        Tipo Original: {document_data.get('document_type_original', 'N/A')}
        
        CONTEÚDO/EMENTA:
        {document_data['document_summary']}
        
        ---
        
        {prompt}
        """
        
        # Aqui seria feita a chamada para o modelo de linguagem
        # Por exemplo, usando OpenAI API, Claude, ou outro LLM
        
        # Simulação da resposta estruturada
        parsed_result = {
            'parsing_prompt_used': prompt[:100] + "...",
            'extraction_confidence': 0.85,
            'structured_data': {
                'document_identification': {},
                'thematic_classification': {},
                'content_analysis': {},
                'regulatory_impact': {},
                'implementation_details': {}
            }
        }
        
        return parsed_result
    
    def _load_specialized_prompts(self):
        """
        Carrega todos os prompts especializados
        """
        
        return {
            'legislation_geral': """[Prompt geral para legislação conforme definido acima]""",
            'legislation_lei_ordinaria': """[Prompt específico para leis ordinárias]""",
            'legislation_decreto': """[Prompt específico para decretos]""",
            'legislation_resolucao': """[Prompt específico para resoluções]""",
            'jurisprudence_geral': """[Prompt geral para jurisprudência]""",
            'jurisprudence_stf_constitucional': """[Prompt específico para STF]""",
            'jurisprudence_stj_uniformizacao': """[Prompt específico para STJ]""",
            'doctrine_geral': """[Prompt geral para doutrina]""",
            'doctrine_tese': """[Prompt específico para teses]""",
            'doctrine_artigo': """[Prompt específico para artigos]""",
            'doctrine_relatorio': """[Prompt específico para relatórios]""",
            'default': """[Prompt padrão para casos não classificados]"""
        }
```

### 4.2 Validação e Controle de Qualidade

```python
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
    
    def validate_parsing_result(self, parsed_content, original_document):
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
        validation_results['overall_quality'] = sum(
            validation_results[key] for key in validation_results 
            if key.endswith('_score')
        ) / 4
        
        # Geração de recomendações
        validation_results['recommendations'] = self._generate_recommendations(validation_results)
        
        return validation_results
    
    def _check_completeness(self, parsed_content):
        """
        Verifica completude das informações extraídas
        """
        
        required_fields = [
            'document_identification',
            'thematic_classification', 
            'content_analysis',
            'regulatory_impact'
        ]
        
        completed_fields = sum(
            1 for field in required_fields 
            if field in parsed_content.get('structured_data', {}) 
            and parsed_content['structured_data'][field]
        )
        
        return completed_fields / len(required_fields)
    
    def _check_accuracy(self, parsed_content, original_document):
        """
        Verifica precisão das informações extraídas
        """
        
        # Verificações básicas de consistência
        accuracy_checks = []
        
        # Verificar se a data extraída está no formato correto
        if 'enacting_date' in parsed_content.get('structured_data', {}).get('document_identification', {}):
            date_format_correct = self._validate_date_format(
                parsed_content['structured_data']['document_identification']['enacting_date']
            )
            accuracy_checks.append(date_format_correct)
        
        # Verificar se o tipo de documento é consistente com a URN
        if 'document_type' in parsed_content.get('structured_data', {}).get('document_identification', {}):
            type_consistency = self._validate_document_type_consistency(
                parsed_content['structured_data']['document_identification']['document_type'],
                original_document.get('urn', '')
            )
            accuracy_checks.append(type_consistency)
        
        return sum(accuracy_checks) / len(accuracy_checks) if accuracy_checks else 0.5
    
    def _generate_recommendations(self, validation_results):
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
```

---

## 5. Integração com Novos Termos de Busca

### 5.1 Sistema de Enriquecimento Temático

```python
class ThematicEnrichmentSystem:
    """
    Sistema de enriquecimento baseado nos novos termos de busca
    """
    
    def __init__(self):
        self.search_terms = self._load_enhanced_search_terms()
        self.thematic_categories = self._load_thematic_categories()
    
    def enrich_document_analysis(self, parsed_content, original_document):
        """
        Enriquece análise com base nos novos termos de busca
        """
        
        text_content = f"{original_document['title']} {original_document['document_summary']}".lower()
        
        # Identificação de temas específicos
        thematic_matches = self._identify_thematic_matches(text_content)
        
        # Classificação de relevância
        relevance_score = self._calculate_thematic_relevance(thematic_matches)
        
        # Identificação de stakeholders
        stakeholders = self._identify_stakeholders(text_content)
        
        # Análise de impacto setorial
        sectoral_impact = self._analyze_sectoral_impact(thematic_matches, text_content)
        
        # Enriquecimento do conteúdo parsed
        enriched_content = {
            **parsed_content,
            'thematic_enrichment': {
                'primary_themes': thematic_matches['primary'],
                'secondary_themes': thematic_matches['secondary'],
                'relevance_score': relevance_score,
                'stakeholders_identified': stakeholders,
                'sectoral_impact': sectoral_impact,
                'regulatory_complexity': self._assess_regulatory_complexity(thematic_matches)
            }
        }
        
        return enriched_content
    
    def _identify_thematic_matches(self, text_content):
        """
        Identifica matches temáticos baseados nos novos termos
        """
        
        matches = {
            'primary': [],
            'secondary': [],
            'scores': {}
        }
        
        for category, terms in self.search_terms.items():
            score = sum(1 for term in terms if term.lower() in text_content)
            
            if score > 0:
                matches['scores'][category] = score / len(terms)
                
                if matches['scores'][category] > 0.3:
                    matches['primary'].append(category)
                elif matches['scores'][category] > 0.1:
                    matches['secondary'].append(category)
        
        return matches
    
    def _identify_stakeholders(self, text_content):
        """
        Identifica stakeholders baseado no conteúdo
        """
        
        stakeholder_patterns = {
            'transportadores': ['transportador', 'caminhoneiro', 'motorista', 'empresa de transporte'],
            'embarcadores': ['embarcador', 'remetente', 'expedidor'],
            'reguladores': ['antt', 'anp', 'aneel', 'ana', 'contran', 'ibama'],
            'fornecedores': ['fabricante', 'montadora', 'distribuidor'],
            'usuarios_finais': ['consumidor', 'destinatário', 'cliente final'],
            'sociedade': ['população', 'comunidade', 'sociedade civil']
        }
        
        identified_stakeholders = []
        
        for stakeholder_type, patterns in stakeholder_patterns.items():
            if any(pattern in text_content for pattern in patterns):
                identified_stakeholders.append(stakeholder_type)
        
        return identified_stakeholders
    
    def _analyze_sectoral_impact(self, thematic_matches, text_content):
        """
        Analisa impacto setorial baseado nos temas identificados
        """
        
        impact_analysis = {
            'direct_impact': [],
            'indirect_impact': [],
            'implementation_complexity': 'medium',
            'compliance_cost': 'medium',
            'timeline_urgency': 'medium'
        }
        
        # Análise de impacto direto
        if 'regulamentacao_normas' in thematic_matches['primary']:
            impact_analysis['direct_impact'].append('compliance_requirements')
        
        if 'incentivos_tributacao' in thematic_matches['primary']:
            impact_analysis['direct_impact'].append('financial_impact')
        
        if 'tecnologia_inovacao' in thematic_matches['primary']:
            impact_analysis['direct_impact'].append('technological_adaptation')
        
        # Análise de complexidade
        complexity_indicators = ['regulamentacao_normas', 'programas_governamentais', 'tecnologia_inovacao']
        complexity_score = sum(1 for indicator in complexity_indicators if indicator in thematic_matches['primary'])
        
        if complexity_score >= 2:
            impact_analysis['implementation_complexity'] = 'high'
        elif complexity_score == 0:
            impact_analysis['implementation_complexity'] = 'low'
        
        return impact_analysis
```

Este sistema de parsing prompts refinados representa uma evolução significativa na capacidade de análise e extração de informações estruturadas dos documentos LexML. A implementação hierárquica permite uma granularidade analítica superior, mantendo a flexibilidade necessária para diferentes tipos de documentos e contextos regulatórios.

A integração com os novos termos de busca garante que a análise seja sempre contextualizada e relevante para o setor de transporte de carga, enquanto o sistema de controle de qualidade assegura a confiabilidade e consistência dos resultados obtidos.

