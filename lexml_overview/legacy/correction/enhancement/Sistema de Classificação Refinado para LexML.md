# Sistema de Classificação Refinado para LexML
## Análise Detalhada e Implementação de Subtipos

**Autor:** Manus AI  
**Data:** 2025-07-12  
**Versão:** 2.0 - Atualizada com Novos Parâmetros  

---

## 1. Análise dos Novos Parâmetros de Pesquisa

### 1.1 Expansão Significativa dos Termos de Busca

A análise do novo arquivo de termos de busca revela uma expansão substancial e estratégica dos parâmetros de monitoramento legislativo. O conjunto original de termos gerais foi refinado em **10 categorias temáticas específicas**, representando uma evolução de aproximadamente 80+ termos de busca organizados sistematicamente.

Esta expansão reflete uma compreensão mais sofisticada do ecossistema regulatório do transporte de carga, incorporando dimensões que vão desde aspectos tecnológicos até questões de sustentabilidade e transição energética. A estruturação temática permite um monitoramento mais granular e direcionado, essencial para capturar nuances regulatórias que poderiam passar despercebidas em buscas mais genéricas.

### 1.2 Categorização Temática Detalhada

#### **Categoria 1: Termos Gerais de Transporte de Carga**
A categoria fundamental mantém os termos clássicos como "transporte de carga" e "transporte rodoviário de carga", mas expande significativamente para incluir terminologias específicas como "logística de carga", "frete/fretamento", e especificações veiculares detalhadas ("caminhão/caminhões", "veículos pesados", "veículos comerciais"). Esta expansão é crucial porque diferentes documentos normativos podem utilizar terminologias variadas para se referir ao mesmo conceito, e a captura abrangente garante maior completude na coleta.

#### **Categoria 2: Combustíveis e Energia**
Esta categoria representa uma das expansões mais significativas, refletindo a crescente importância da transição energética no setor de transportes. A inclusão de termos como "gás natural veicular", "biometano", "diesel verde", "hidrogênio", e "célula de combustível" demonstra uma antecipação das tendências regulatórias futuras. Particularmente relevante é a inclusão de termos emergentes como "HVO" (Hydrotreated Vegetable Oil) e "algas marinhas", indicando uma perspectiva de longo prazo sobre combustíveis alternativos.

#### **Categoria 3: Eficiência Energética e Emissões**
O foco em "eficiência energética", "emissões", "descarbonização" e "gases de efeito estufa" alinha-se com as tendências globais de regulamentação ambiental. A inclusão específica de "rotulagem veicular" e "consumo de combustível" sugere uma antecipação de regulamentações mais detalhadas sobre transparência e performance energética de veículos comerciais.

#### **Categoria 4: Tecnologia e Inovação**
A incorporação de "tecnologias assistivas", "veículos autônomos", "telemetria" e "rastreamento" reflete a digitalização crescente do setor de transportes. Estes termos são particularmente importantes porque representam áreas onde a regulamentação frequentemente segue a inovação tecnológica, criando oportunidades para monitoramento proativo de mudanças normativas.

#### **Categoria 5: Infraestrutura**
A especificação de "postos de abastecimento", "terminais de carga", "centros de distribuição" e "armazéns" reconhece que a regulamentação do transporte de carga não se limita aos veículos, mas abrange toda a cadeia logística. Esta perspectiva sistêmica é essencial para capturar regulamentações que impactam indiretamente o transporte através da infraestrutura de apoio.

### 1.3 Integração com Órgãos Reguladores

A inclusão específica de órgãos como "CONTRAN", "ANTT", "CNPE", "CCEE", "ANA", "ANP", e "ONS" demonstra uma compreensão sofisticada do ecossistema regulatório brasileiro. Esta abordagem permite não apenas capturar regulamentações por tema, mas também por origem institucional, facilitando análises sobre padrões de atuação de diferentes órgãos reguladores.

### 1.4 Dimensão Econômica e Tributária

A categoria de "Incentivos e Tributação" com termos como "IPI", "ICMS", "incentivo fiscal", "isenção" e "benefício tributário" reconhece que a regulamentação do transporte de carga frequentemente utiliza instrumentos econômicos para influenciar comportamentos. Esta dimensão é crucial para compreender o impacto econômico das mudanças regulatórias.

### 1.5 Programas Governamentais Específicos

A inclusão de "Rota 2030", "Paten", "Programa de Aceleração da Transição Energética" e "Lei do Combustível do Futuro" demonstra uma abordagem proativa, antecipando regulamentações associadas a programas governamentais específicos. Esta estratégia é particularmente valiosa porque permite capturar regulamentações em estágios iniciais de desenvolvimento.

---

## 2. Sistema de Classificação Refinado

### 2.1 Metodologia de Classificação Hierárquica

O sistema de classificação refinado implementa uma estrutura hierárquica de três níveis: **Categoria Principal** → **Tipo** → **Subtipo**. Esta estrutura permite uma granularidade analítica superior, mantendo a simplicidade conceitual necessária para análises agregadas.

A metodologia baseia-se na análise sistemática de padrões de URN (Uniform Resource Name) do sistema LexML, combinada com análise de conteúdo textual dos documentos. A classificação utiliza uma abordagem híbrida que combina regras determinísticas baseadas em padrões conhecidos com análise probabilística de conteúdo textual.

### 2.2 Classificação Detalhada de Legislação

#### **2.2.1 Legislação Federal**

**Leis Ordinárias**
As leis ordinárias representam o instrumento legislativo mais comum e abrangente, requerendo maioria simples para aprovação. No contexto do transporte de carga, estas leis frequentemente estabelecem marcos regulatórios amplos, definindo princípios, diretrizes e estruturas institucionais. Exemplos incluem leis que criam agências reguladoras, estabelecem regimes jurídicos para setores específicos, ou definem políticas nacionais de transporte.

**Leis Complementares**
As leis complementares, que requerem maioria absoluta para aprovação, são utilizadas para regulamentar matérias específicas previstas na Constituição. No transporte de carga, são particularmente relevantes para questões tributárias (como ICMS sobre combustíveis), competências de entes federativos, e regulamentação de setores com impacto constitucional significativo.

**Medidas Provisórias**
As medidas provisórias representam instrumentos de urgência do Poder Executivo, com força de lei imediata. No setor de transportes, são frequentemente utilizadas para responder a crises (como greves de caminhoneiros), implementar mudanças tributárias emergenciais, ou criar programas governamentais com necessidade de implementação imediata.

**Decretos Legislativos**
Os decretos legislativos são utilizados pelo Congresso Nacional para matérias de sua competência exclusiva, como aprovação de tratados internacionais, autorização para empréstimos externos, ou sustação de atos normativos do Poder Executivo. No transporte de carga, são relevantes para acordos internacionais de transporte e aprovação de financiamentos para infraestrutura.

#### **2.2.2 Legislação do Poder Executivo**

**Decretos Presidenciais**
Os decretos presidenciais são utilizados para regulamentar leis, organizar a administração pública, e implementar políticas governamentais. No transporte de carga, são instrumentos fundamentais para regulamentação detalhada de aspectos técnicos, criação de programas governamentais, e estabelecimento de procedimentos administrativos.

**Decretos Regulamentares**
Subconjunto específico dos decretos presidenciais, focados exclusivamente na regulamentação de leis. Estes decretos detalham aspectos técnicos e procedimentais necessários para implementação de marcos legais, sendo cruciais para a operacionalização de políticas de transporte.

**Decretos de Organização Administrativa**
Decretos focados na estruturação de órgãos e entidades da administração pública. No contexto do transporte, são relevantes para criação de secretarias, departamentos, e agências, bem como para definição de competências e estruturas organizacionais.

#### **2.2.3 Atos Normativos de Órgãos Reguladores**

**Portarias Ministeriais**
As portarias são instrumentos normativos utilizados por ministros para regulamentar matérias de sua competência. No transporte de carga, são particularmente importantes as portarias dos Ministérios dos Transportes, da Infraestrutura, de Minas e Energia, e do Meio Ambiente, que frequentemente estabelecem normas técnicas, procedimentos administrativos, e diretrizes setoriais.

**Instruções Normativas**
As instruções normativas são utilizadas por órgãos da administração pública para detalhar procedimentos administrativos e interpretar normas superiores. No contexto do transporte de carga, são fundamentais para compreender como as regulamentações são implementadas na prática, estabelecendo procedimentos para licenciamento, fiscalização, e cumprimento de obrigações.

**Resoluções de Agências Reguladoras**
As resoluções são os principais instrumentos normativos das agências reguladoras, estabelecendo normas técnicas e regulamentações setoriais. Para o transporte de carga, são particularmente relevantes as resoluções da ANTT (transporte terrestre), ANP (combustíveis), ANEEL (energia elétrica), e ANA (recursos hídricos).

#### **2.2.4 Legislação Estadual e Municipal**

**Leis Estaduais**
As leis estaduais são relevantes para o transporte de carga principalmente em questões tributárias (ICMS), licenciamento ambiental, e regulamentação de transporte intermunicipal. A competência concorrente em matéria de transporte permite aos estados legislar sobre aspectos específicos não regulamentados pela União.

**Decretos Estaduais**
Os decretos estaduais regulamentam leis estaduais e organizam a administração estadual. No transporte de carga, são relevantes para regulamentação de ICMS sobre combustíveis, procedimentos de licenciamento, e organização de órgãos estaduais de transporte.

**Leis Municipais**
As leis municipais impactam o transporte de carga principalmente através de regulamentações urbanas, como restrições de circulação, zoneamento para terminais de carga, e regulamentação de transporte municipal de cargas.

### 2.3 Classificação Detalhada de Jurisprudência

#### **2.3.1 Supremo Tribunal Federal (STF)**

**Ações Diretas de Inconstitucionalidade (ADI)**
As ADIs representam o controle concentrado de constitucionalidade, sendo fundamentais para compreender a interpretação constitucional de normas relacionadas ao transporte de carga. Decisões em ADIs têm efeito vinculante e erga omnes, impactando diretamente a aplicação de regulamentações setoriais.

**Ações Declaratórias de Constitucionalidade (ADC)**
As ADCs são utilizadas para declarar a constitucionalidade de leis ou atos normativos quando há controvérsia judicial relevante. No transporte de carga, são importantes para consolidar a validade de marcos regulatórios contestados.

**Arguições de Descumprimento de Preceito Fundamental (ADPF)**
As ADPFs são utilizadas quando não há outro meio eficaz de sanar lesividade a preceito fundamental. No contexto do transporte, podem ser relevantes para questões que envolvem direitos fundamentais afetados por regulamentações setoriais.

**Recursos Extraordinários (RE)**
Os recursos extraordinários permitem ao STF uniformizar a interpretação constitucional em casos concretos. Decisões em RE com repercussão geral têm efeito vinculante, sendo cruciais para compreender a aplicação prática de normas constitucionais ao transporte de carga.

#### **2.3.2 Superior Tribunal de Justiça (STJ)**

**Recursos Especiais (REsp)**
Os recursos especiais são o principal instrumento do STJ para uniformizar a interpretação de legislação federal. No transporte de carga, são fundamentais para compreender como normas federais são interpretadas e aplicadas pelos tribunais inferiores.

**Recursos Ordinários em Mandado de Segurança (RMS)**
Os RMS são relevantes para questões administrativas relacionadas ao transporte de carga, como licenciamentos, autorizações, e procedimentos regulatórios contestados judicialmente.

**Conflitos de Competência**
A resolução de conflitos de competência pelo STJ é importante para definir qual justiça (federal, estadual, trabalhista) deve julgar questões específicas relacionadas ao transporte de carga.

#### **2.3.3 Tribunais Regionais Federais (TRF)**

**Apelações Cíveis**
As apelações cíveis em matéria de transporte de carga frequentemente envolvem questões regulatórias, tributárias, e administrativas, fornecendo insights sobre a aplicação prática de normas federais.

**Mandados de Segurança**
Os mandados de segurança são instrumentos importantes para contestar atos administrativos de órgãos reguladores, sendo relevantes para compreender limites e procedimentos da regulamentação setorial.

**Ações Ordinárias**
As ações ordinárias podem envolver questões contratuais, responsabilidade civil, e interpretação de normas regulatórias no contexto do transporte de carga.

#### **2.3.4 Tribunais de Justiça Estaduais**

**Apelações em Matéria Tributária**
As apelações relacionadas a ICMS sobre combustíveis e transporte são particularmente relevantes para compreender a aplicação de normas tributárias estaduais.

**Ações Ambientais**
As ações relacionadas a licenciamento ambiental e impactos ambientais do transporte de carga fornecem insights sobre a interface entre regulamentação ambiental e transporte.

#### **2.3.5 Justiça Trabalhista**

**Dissídios Coletivos**
Os dissídios coletivos envolvendo categorias do transporte de carga são relevantes para compreender questões trabalhistas específicas do setor.

**Recursos Ordinários**
Os recursos ordinários em questões trabalhistas específicas do transporte de carga, como jornada de trabalho de motoristas e condições de trabalho.

### 2.4 Classificação Detalhada de Doutrina

#### **2.4.1 Produção Acadêmica**

**Teses de Doutorado**
As teses de doutorado representam a produção acadêmica mais aprofundada, frequentemente explorando aspectos teóricos e empíricos específicos do transporte de carga. Estas produções são valiosas para compreender tendências de pesquisa, lacunas no conhecimento, e perspectivas acadêmicas sobre regulamentação setorial.

**Dissertações de Mestrado**
As dissertações de mestrado, embora menos aprofundadas que teses de doutorado, frequentemente abordam questões práticas e aplicadas do transporte de carga, fornecendo insights sobre implementação de políticas e impactos regulatórios.

**Trabalhos de Conclusão de Curso (TCC)**
Os TCCs, embora de menor profundidade acadêmica, podem fornecer perspectivas atualizadas sobre questões emergentes e aplicações práticas de regulamentações recentes.

#### **2.4.2 Artigos Científicos**

**Artigos em Periódicos Nacionais**
Os artigos em periódicos nacionais frequentemente abordam questões específicas do contexto brasileiro, incluindo análises de políticas públicas, estudos de caso, e avaliações de impacto regulatório.

**Artigos em Periódicos Internacionais**
Os artigos em periódicos internacionais permitem comparações com experiências de outros países, identificação de melhores práticas, e compreensão de tendências globais em regulamentação de transporte.

**Artigos de Revisão**
Os artigos de revisão consolidam o conhecimento existente sobre temas específicos, sendo valiosos para compreender o estado da arte em questões regulatórias do transporte de carga.

#### **2.4.3 Livros e Capítulos**

**Livros Especializados**
Os livros especializados em transporte de carga, logística, e regulamentação setorial fornecem análises abrangentes e estruturadas sobre aspectos teóricos e práticos do setor.

**Capítulos de Livros**
Os capítulos de livros frequentemente abordam aspectos específicos de temas mais amplos, sendo valiosos para análises focalizadas em questões particulares.

**Manuais Técnicos**
Os manuais técnicos, frequentemente produzidos por órgãos governamentais ou associações setoriais, fornecem orientações práticas para implementação de regulamentações.

#### **2.4.4 Documentos Institucionais**

**Relatórios de Pesquisa**
Os relatórios de pesquisa produzidos por instituições de pesquisa, consultorias, e órgãos governamentais frequentemente contêm análises detalhadas sobre aspectos específicos do transporte de carga.

**Estudos de Impacto**
Os estudos de impacto regulatório e ambiental são fundamentais para compreender as justificativas e consequências esperadas de mudanças regulatórias.

**Pareceres Técnicos**
Os pareceres técnicos produzidos por especialistas e instituições fornecem análises especializadas sobre questões regulatórias específicas.

#### **2.4.5 Documentos de Organizações Setoriais**

**Publicações de Associações**
As publicações de associações setoriais (como CNT, ANTF, ABCAM) fornecem perspectivas do setor privado sobre regulamentações e políticas públicas.

**Estudos de Consultorias**
Os estudos produzidos por consultorias especializadas frequentemente abordam aspectos econômicos e técnicos de regulamentações setoriais.

**Relatórios de Organismos Internacionais**
Os relatórios de organismos como OECD, Banco Mundial, e IEA fornecem perspectivas internacionais e comparativas sobre regulamentação de transporte.

---

## 3. Implementação Técnica do Sistema de Classificação

### 3.1 Algoritmo de Classificação Hierárquica

```python
class RefinedDocumentClassifier:
    """
    Sistema de classificação refinado para documentos LexML
    Implementa classificação hierárquica em três níveis
    """
    
    def __init__(self):
        self.legislation_patterns = self._load_legislation_patterns()
        self.jurisprudence_patterns = self._load_jurisprudence_patterns()
        self.doctrine_patterns = self._load_doctrine_patterns()
        
    def classify_document(self, urn, title, document_summary, document_type_original):
        """
        Classifica documento em categoria, tipo e subtipo
        """
        
        # Classificação de primeiro nível (categoria principal)
        main_category = self._classify_main_category(urn, title, document_summary)
        
        # Classificação de segundo nível (tipo)
        document_type = self._classify_type(main_category, urn, title, document_summary)
        
        # Classificação de terceiro nível (subtipo)
        document_subtype = self._classify_subtype(main_category, document_type, urn, title, document_summary)
        
        return {
            'main_category': main_category,
            'document_type': document_type,
            'document_subtype': document_subtype,
            'classification_confidence': self._calculate_confidence(urn, title, document_summary)
        }
    
    def _classify_main_category(self, urn, title, document_summary):
        """
        Classifica categoria principal: legislation, jurisprudence, doctrine
        """
        
        urn_lower = urn.lower()
        
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
        leg_count = sum(1 for indicator in legislation_indicators if indicator.replace('.', ' ') in text_content)
        jur_count = sum(1 for indicator in jurisprudence_indicators if indicator.replace('.', ' ') in text_content)
        
        if leg_count > jur_count and leg_count > 0:
            return 'legislation'
        elif jur_count > 0:
            return 'jurisprudence'
        else:
            return 'doctrine'
    
    def _classify_legislation_type(self, urn, title, document_summary):
        """
        Classifica tipos específicos de legislação
        """
        
        urn_lower = urn.lower()
        text_content = f"{title} {document_summary}".lower()
        
        # Padrões específicos de legislação
        legislation_types = {
            'lei_ordinaria': ['lei:', 'lei.ordinaria', 'lei.federal'],
            'lei_complementar': ['lei.complementar', 'lc.'],
            'medida_provisoria': ['medida.provisoria', 'mp.', 'mp:'],
            'decreto_presidencial': ['decreto:', 'decreto.presidencial'],
            'decreto_legislativo': ['decreto.legislativo', 'decreto.do.congresso'],
            'portaria_ministerial': ['portaria:', 'portaria.ministerial'],
            'resolucao_agencia': ['resolucao:', 'resolucao.antt', 'resolucao.anp', 'resolucao.aneel'],
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
    
    def _classify_jurisprudence_type(self, urn, title, document_summary):
        """
        Classifica tipos específicos de jurisprudência
        """
        
        urn_lower = urn.lower()
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
        
        # Verificação por URN
        for jur_type, patterns in jurisprudence_types.items():
            pattern_match = all(any(p in urn_lower for p in patterns) for p in patterns[:2]) if len(patterns) > 1 else any(p in urn_lower for p in patterns)
            if pattern_match:
                return jur_type
        
        # Verificação por conteúdo textual
        for jur_type, patterns in jurisprudence_types.items():
            pattern_match = sum(1 for p in patterns if p.replace('.', ' ') in text_content) >= 2
            if pattern_match:
                return jur_type
        
        return 'jurisprudencia_geral'
    
    def _classify_doctrine_type(self, urn, title, document_summary):
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
    
    def _classify_subtype(self, main_category, document_type, urn, title, document_summary):
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
    
    def _classify_legislation_subtype(self, document_type, urn, title, document_summary):
        """
        Classifica subtipos de legislação baseado no conteúdo temático
        """
        
        text_content = f"{title} {document_summary}".lower()
        
        # Subtipos temáticos baseados nos novos termos de busca
        thematic_subtypes = {
            'combustiveis_energia': [
                'gas natural', 'biometano', 'diesel', 'biodiesel', 'hidrogênio',
                'etanol', 'combustível', 'energia', 'renovável'
            ],
            'eficiencia_emissoes': [
                'eficiência energética', 'emissões', 'descarbonização',
                'gases efeito estufa', 'rotulagem veicular', 'consumo combustível'
            ],
            'tecnologia_inovacao': [
                'tecnologias assistivas', 'veículos autônomos', 'telemetria',
                'rastreamento', 'motorização', 'conversão'
            ],
            'infraestrutura': [
                'postos abastecimento', 'terminais carga', 'centros distribuição',
                'armazéns', 'infraestrutura'
            ],
            'regulamentacao_normas': [
                'contran', 'antt', 'registro', 'habilitação', 'licenciamento',
                'rntrc', 'segurança veicular'
            ],
            'incentivos_tributacao': [
                'ipi', 'icms', 'incentivo fiscal', 'isenção', 'benefício tributário',
                'financiamento'
            ],
            'programas_governamentais': [
                'rota 2030', 'paten', 'transição energética', 'mobilidade logística',
                'desenvolvimento sustentável'
            ],
            'maquinas_equipamentos': [
                'máquinas agrícolas', 'implementos rodoviários', 'reboque',
                'semi-reboque', 'carreta', 'bitrem', 'rodotrem'
            ],
            'operacoes_servicos': [
                'transportador autônomo', 'empresa transporte', 'operador logístico',
                'embarcador', 'terceirização', 'contrato frete'
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
    
    def _calculate_confidence(self, urn, title, document_summary):
        """
        Calcula confiança da classificação baseada na qualidade dos indicadores
        """
        
        confidence_factors = {
            'urn_clarity': 0.4,  # Clareza da URN
            'title_relevance': 0.3,  # Relevância do título
            'content_indicators': 0.3  # Indicadores no conteúdo
        }
        
        # Avaliação da clareza da URN
        urn_score = 1.0 if any(indicator in urn.lower() for indicator in ['lei', 'decreto', 'portaria', 'resolucao', 'jurisprudencia']) else 0.5
        
        # Avaliação da relevância do título
        title_score = 1.0 if len(title) > 20 and any(word in title.lower() for word in ['transporte', 'carga', 'veículo', 'combustível']) else 0.7
        
        # Avaliação dos indicadores de conteúdo
        content_score = 1.0 if len(document_summary) > 50 else 0.6
        
        # Cálculo da confiança ponderada
        confidence = (
            urn_score * confidence_factors['urn_clarity'] +
            title_score * confidence_factors['title_relevance'] +
            content_score * confidence_factors['content_indicators']
        )
        
        return round(confidence, 2)
```

### 3.2 Integração com Novos Termos de Busca

```python
class EnhancedSearchTermsProcessor:
    """
    Processador aprimorado para os novos termos de busca
    Implementa busca booleana e categorização temática
    """
    
    def __init__(self):
        self.search_categories = self._load_search_categories()
        self.boolean_combinations = self._load_boolean_combinations()
        
    def _load_search_categories(self):
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
    
    def _load_boolean_combinations(self):
        """
        Carrega combinações booleanas sugeridas
        """
        return [
            '("transporte de carga" OR "veículos pesados") AND ("gás natural" OR biometano OR biodiesel)',
            '(caminhão OR "veículo pesado") AND (incentivo OR benefício OR isenção)',
            '("eficiência energética" OR emissões) AND ("transporte rodoviário" OR logística)',
            '(Rota 2030 OR Paten) AND (transporte OR logística OR carga)'
        ]
    
    def generate_comprehensive_search_query(self, categories=None, include_legal_terms=True):
        """
        Gera consulta de busca abrangente
        """
        
        if categories is None:
            categories = list(self.search_categories.keys())
        
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
            legal_terms = ['lei', 'decreto', 'portaria', 'resolução', 'medida provisória', 'projeto de lei', 'instrução normativa']
            legal_query = '(' + ' OR '.join(legal_terms) + ')'
            main_query = f'({main_query}) AND {legal_query}'
        
        return main_query
    
    def categorize_search_results(self, results):
        """
        Categoriza resultados de busca por tema
        """
        
        categorized_results = {category: [] for category in self.search_categories.keys()}
        
        for result in results:
            text_content = f"{result.get('title', '')} {result.get('document_summary', '')}".lower()
            
            # Identificar categorias relevantes
            for category, terms in self.search_categories.items():
                matches = sum(1 for term in terms if term.lower() in text_content)
                if matches > 0:
                    categorized_results[category].append({
                        **result,
                        'category_matches': matches,
                        'category_relevance': matches / len(terms)
                    })
        
        return categorized_results
```

