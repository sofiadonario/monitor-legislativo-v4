# Monitor Legislativo v4 - Documentação Completa

🇧🇷 **Centro de documentação** para o Monitor Legislativo v4, organizado por categoria e público-alvo para atender pesquisadores, desenvolvedores e gestores do sistema de monitoramento legislativo brasileiro.

---

## 🎯 Navegação por Público-Alvo

### 👩‍🔬 Para Pesquisadores Acadêmicos
**Ferramentas e guias para pesquisa legislativa brasileira**
- **[Guia de Início Rápido - Pesquisadores](getting-started/researchers-quickstart.md)** - Primeiros passos para usar o sistema
- **[Guia de Legislação de Transporte](guides/guia-legislacao-transporte.md)** - Manual específico para pesquisa em transporte
- **[Geração de Citações ABNT](guides/citations-abnt-guide.md)** - Como gerar citações acadêmicas
- **[Relatórios de Análise](reports/analytics/)** - Relatórios e análises de dados disponíveis
- **[Manual do Usuário](USER_GUIDE.md)** - Guia completo de funcionalidades

### 👨‍💻 Para Desenvolvedores R
**Desenvolvimento e customização em ambiente R**
- **[Guia de Início Rápido - R](getting-started/r-developers-quickstart.md)** - Setup para desenvolvedores R
- **[Estrutura do Projeto](guides/project-structure.md)** - Organização do código R-Shiny
- **[APIs e Integração de Dados](guides/api-integration.md)** - Como integrar com fontes de dados
- **[Configuração do Banco de Dados](guides/database-configuration-guide.md)** - Setup do PostgreSQL
- **[Módulos e Componentes](architecture/r-modules-reference.md)** - Documentação dos módulos R

### 🏗️ Para Desenvolvedores Full-Stack
**Arquitetura completa e deployment**
- **[Guia de Início Rápido - Full-Stack](getting-started/fullstack-quickstart.md)** - Setup completo do ambiente
- **[Arquitetura do Sistema](architecture/system-overview.md)** - Visão geral da arquitetura
- **[Guias de Deployment](deployment/)** - Railway, AWS e outras plataformas
- **[Esquema do Banco de Dados](architecture/database-schema.md)** - Estrutura e relacionamentos
- **[Monitoramento e Performance](operation-guides/MONITORING_ALERTING_GUIDE.md)** - Observabilidade do sistema

### ⚙️ Para Administradores de Sistema
**Operação e manutenção em produção**
- **[Lista de Verificação de Deployment](deployment/DEPLOYMENT_CHECKLIST.md)** - Checklist pré-produção
- **[Guia de Segurança e Conformidade](operation-guides/SECURITY_COMPLIANCE_GUIDE.md)** - LGPD e boas práticas
- **[Otimização de Banco de Dados](operation-guides/DATABASE_OPTIMIZATION_GUIDE.md)** - Performance e manutenção
- **[Análise de Custos](operation-guides/MONTHLY_COST_ANALYSIS.md)** - Gestão financeira da infraestrutura
- **[Load Balancer NGINX](operation-guides/NGINX_LOAD_BALANCER_GUIDE.md)** - Configuração de balanceamento

### 📊 Para Gestores de Projeto
**Acompanhamento e planejamento estratégico**
- **[Resumo Executivo](RESUMO_EXECUTIVO_FINAL.md)** - Visão geral do projeto
- **[Relatórios de Progresso](reports/)** - Status e entregas por fase
- **[Roadmap de Desenvolvimento](ROADMAP-R-Architecture-Consolidation.md)** - Planejamento técnico
- **[Estratégia de Dados](DATA_MANAGEMENT_STRATEGY.md)** - Governança de dados legislativos

---

## 📚 Estrutura da Documentação

### 🚀 Guias de Início (`/getting-started/`)
**Primeiros passos personalizados por perfil de usuário**
- **researchers-quickstart.md** - Guia para pesquisadores acadêmicos
- **r-developers-quickstart.md** - Setup para desenvolvedores R
- **fullstack-quickstart.md** - Environment completo para full-stack
- **system-admin-quickstart.md** - Guia para administradores de sistema

### 🏗️ Arquitetura e Diagramas (`/architecture/`)
**Documentação técnica da arquitetura do sistema**
- **system-overview.md** - Visão geral da arquitetura
- **database-schema.md** - Esquema completo do banco de dados
- **r-modules-reference.md** - Documentação dos módulos R
- **data-flow-diagrams.md** - Fluxos de dados e processamento
- **integration-architecture.md** - Arquitetura de integrações externas
- **Diagramas Mermaid existentes**: sistema, pipeline, database ER

### 📖 Guias Técnicos (`/guides/`)
**Documentação detalhada por funcionalidade**
- **project-structure.md** - Organização do código e arquivos
- **api-integration.md** - Integração com APIs externas
- **database-configuration-guide.md** - Configuração do PostgreSQL
- **citations-abnt-guide.md** - Geração de citações acadêmicas
- **guia-legislacao-transporte.md** - Manual de legislação de transporte
- **supabase-integration-prd.md** - Integração com Supabase (legado)

### 🚀 Deployment e Infraestrutura (`/deployment/`)
**Guias de implantação em diferentes ambientes**
- **DEPLOYMENT_CHECKLIST.md** - Lista de verificação pré-deploy
- **DEPLOYMENT_INSTRUCTIONS.md** - Instruções passo a passo
- **RAILWAY_DEPLOYMENT_CHECKLIST.md** - Deploy específico para Railway
- **aws-mackintegridade-deployment/** - Configuração AWS para Mackenzie
- **DOCKER_WSL_SETUP.md** - Setup Docker no Windows WSL

### 📊 Relatórios e Análises (`/reports/`)
**Documentação de análises técnicas e de negócio**
- **analytics/** - Relatórios de análise de dados legislativos
- **technical/** - Análises técnicas e performance
- **project-status/** - Relatórios de progresso e entregas
- **compliance/** - Relatórios de conformidade LGPD/ABNT

### ⚙️ Guias Operacionais (`/operation-guides/`)
**Documentação para operação em produção**
- **MONITORING_ALERTING_GUIDE.md** - Sistema de monitoramento
- **SECURITY_COMPLIANCE_GUIDE.md** - Segurança e conformidade
- **DATABASE_OPTIMIZATION_GUIDE.md** - Otimização de performance
- **MONTHLY_COST_ANALYSIS.md** - Análise de custos operacionais
- **NGINX_LOAD_BALANCER_GUIDE.md** - Configuração de load balancer

### 🗃️ Documentação Histórica (`/legacy/`)
**Materiais históricos e versões depreciadas**
- **PRD: LexML Brasil Integration Fix.d** - PRD legado
- **lexml_implementation_instructions.pdf** - Instruções originais LexML
- **useful screenshots/** - Screenshots históricos

---

## 📋 Padrões de Documentação

### 🇧🇷 Diretrizes de Escrita
**Seguindo padrões acadêmicos brasileiros e boas práticas técnicas**

#### **Linguagem e Tom**
- **Clareza e concisão**: Linguagem técnica acessível
- **Público-alvo específico**: Conteúdo adaptado por audiência
- **Terminologia consistente**: Glossário padrão para termos técnicos
- **Português brasileiro formal**: Para documentação oficial
- **Inglês técnico**: Para código e APIs quando necessário

#### **Estrutura e Formato**
- **Headers hierárquicos**: Estrutura clara com H1-H6
- **Exemplos práticos**: Código funcional e casos de uso reais
- **Cross-references**: Links internos para documentação relacionada
- **Versionamento**: Datas de atualização e histórico de versões
- **Markdown padronizado**: Formatação consistente

#### **Conformidade ABNT**
- **Citações acadêmicas**: Formato ABNT para referências
- **Numeração de seções**: Seguindo NBR 6024
- **Referências bibliográficas**: NBR 6023 para fontes externas
- **Estrutura de documentos**: NBR 14724 para trabalhos acadêmicos
- **Glossário e índices**: NBR 14536 para terminologia

### 📝 Tipos de Documento

#### **🚀 Documentos de Deployment**
- Procedimentos de configuração de ambiente
- Requisitos técnicos e dependências
- Considerações de segurança e compliance
- Guias de troubleshooting e resolução de problemas

#### **📖 Guias Técnicos**
- Procedimentos de integração step-by-step
- Documentação de APIs com exemplos
- Referências de configuração
- Boas práticas de desenvolvimento

#### **📊 Relatórios de Análise**
- Análises técnicas de performance
- Avaliações de qualidade de dados
- Sumários de entregas por fase
- Atualizações de status do projeto

#### **🗃️ Materiais Legados**
- Documentação depreciada para referência
- Referências históricas do projeto
- Screenshots e materiais visuais antigos
- Especificações arquivadas

---

## 🔍 Como Encontrar Documentação

### 📋 Por Tópico Técnico
- **Deployment e Infrastructure**: Consulte `/deployment/` e `/operation-guides/`
- **Banco de Dados**: Veja `/guides/database-configuration-guide.md` e `/architecture/database-schema.md`
- **Integrações de API**: Revise `/guides/api-integration.md` e `/architecture/integration-architecture.md`
- **Performance e Monitoramento**: Consulte `/operation-guides/` e `/reports/technical/`
- **Análise de Dados**: Explore `/reports/analytics/` e `/guides/citations-abnt-guide.md`
- **Histórico do Projeto**: Navegue em `/legacy/` para materiais arquivados

### 👥 Por Público-Alvo
- **Pesquisadores Acadêmicos**: Comece com `/getting-started/researchers-quickstart.md`
- **Desenvolvedores R**: Inicie com `/getting-started/r-developers-quickstart.md`
- **Desenvolvedores Full-Stack**: Vá para `/getting-started/fullstack-quickstart.md`
- **Administradores de Sistema**: Foque em `/deployment/` e `/operation-guides/`
- **Gestores de Projeto**: Consulte `/reports/project-status/` e resumos executivos

### 🎯 Por Fase de Desenvolvimento
- **Planejamento**: `/reports/project-status/` e documentos de roadmap
- **Desenvolvimento**: `/guides/` e `/architecture/`
- **Testes**: `/guides/` para procedimentos de teste
- **Deployment**: `/deployment/` para todos os ambientes
- **Operação**: `/operation-guides/` para manutenção
- **Pesquisa**: `/guides/citations-abnt-guide.md` e `/reports/analytics/`

---

## 📝 Contribuindo com a Documentação

### ➕ Adicionando Novos Documentos
**Processo padronizado para novos conteúdos**

1. **Identifique a categoria apropriada**:
   - `/getting-started/` - Guias de início por público-alvo
   - `/architecture/` - Documentação técnica de sistema
   - `/guides/` - Guias detalhados por funcionalidade
   - `/deployment/` - Procedimentos de implantação
   - `/reports/` - Análises e relatórios
   - `/operation-guides/` - Guias operacionais
   - `/legacy/` - Materiais históricos

2. **Siga as convenções de nomenclatura**:
   - Formato kebab-case (ex: `database-setup-guide.md`)
   - Nomes descritivos e específicos
   - Prefixos por público quando aplicável (`researchers-`, `admin-`, `dev-`)

3. **Estrutura padrão de documento**:
   ```markdown
   # Título do Documento
   
   **Público-alvo**: [Pesquisadores/Desenvolvedores/Admins/Gestores]
   **Última atualização**: [Data]
   **Versão**: [Versão]
   
   ## Resumo Executivo
   
   ## Conteúdo Principal
   
   ## Referências (formato ABNT quando aplicável)
   ```

4. **Atualize este README**: Adicione descrição na seção apropriada
5. **Cross-reference**: Crie links de/para documentos relacionados
6. **Revise conformidade ABNT**: Para documentos acadêmicos

### ✏️ Atualizando Documentos Existentes
**Processo de manutenção da documentação**

1. **Mantenha histórico de versões**: Header com datas de modificação
2. **Atualize datas**: Campo "Última atualização" sempre atual
3. **Preserve compatibilidade**: Mantenha procedimentos críticos funcionais
4. **Archive quando necessário**: Mova versões obsoletas para `/legacy/`
5. **Valide links**: Certifique-se que cross-references funcionam
6. **Teste procedimentos**: Valide instruções em ambiente limpo

---

## 🔄 Cronograma de Manutenção

### 📅 Atualizações Regulares
**Calendário de manutenção da documentação**

- **Mensal**: Revisão de documentação de deployment para precisão
- **Por Release**: Atualização de guias técnicos com novas features
- **Por Fase de Projeto**: Criação de relatórios de entrega e status
- **Conforme Necessário**: Arquivamento de materiais obsoletos
- **Semestral**: Revisão de conformidade ABNT em documentos acadêmicos
- **Anual**: Auditoria completa da estrutura de documentação

### ✅ Garantia de Qualidade
**Checklist de validação da documentação**

- **Links e Referências**: Verificar funcionamento de todos os links
- **Procedimentos de Deployment**: Testar em ambientes limpos
- **Exemplos de Código**: Validar funcionamento dos snippets
- **Screenshots e Visuais**: Garantir que imagens estão atualizadas
- **Conformidade ABNT**: Revisar citações e formato acadêmico
- **Multilingual Consistency**: Sincronizar versões PT-BR e EN
- **Cross-platform Testing**: Validar em diferentes SOs (Windows/Linux/macOS)

---

## 📞 Suporte à Documentação

### 🔍 Para Questões sobre Documentação
**Fluxo recomendado para resolver dúvidas**

1. **Consulte documentos existentes** nas categorias relevantes
2. **Revise cross-references** e materiais relacionados
3. **Consulte documentos de planejamento** para contexto histórico
4. **Refira aos comentários do código** para detalhes de implementação
5. **Verifique issues no GitHub** para discussões técnicas
6. **Contate a equipe acadêmica** para questões de pesquisa

### 📧 Contatos por Especialidade
- **Questões Técnicas (R/Shiny)**: Desenvolvedores R da equipe
- **Arquitetura e Infrastructure**: Equipe DevOps/SysAdmin
- **Conformidade ABNT**: Coordenação acadêmica
- **Pesquisa Legislativa**: Pesquisadores especialistas em direito
- **Integração de Dados**: Especialistas em LexML e fontes governamentais

### 📋 Processo de Feedback
1. **Identifique o tipo de feedback**: Correção, melhoria, novo conteúdo
2. **Use o template apropriado**: Issues ou merge requests
3. **Inclua contexto**: Público-alvo e caso de uso
4. **Sugira melhorias específicas**: Quando possível, proponha soluções
5. **Indique urgência**: Critical, High, Medium, Low

---

## 📖 Estratégia de Conteúdo Multi-Audiência

### 🎯 Abordagem Personalizada
**Estratégia de comunicação por perfil de usuário**

Esta documentação segue uma **estratégia de conteúdo diferenciada** que reconhece as diferentes necessidades informacionais dos usuários do Monitor Legislativo v4:

#### **Pesquisadores Acadêmicos** 🎓
- **Foco**: Metodologia, conformidade ABNT, resultados de pesquisa
- **Tom**: Formal acadêmico, terminologia jurídica precisa
- **Formato**: Estrutura de paper acadêmico, citações completas

#### **Desenvolvedores Técnicos** 💻
- **Foco**: APIs, código, arquitetura, troubleshooting
- **Tom**: Técnico direto, orientado a soluções
- **Formato**: Code snippets, exemplos práticos, flowcharts

#### **Administradores de Sistema** ⚙️
- **Foco**: Deployment, monitoramento, segurança, performance
- **Tom**: Operacional, orientado a procedimentos
- **Formato**: Checklists, comandos, alertas de segurança

#### **Gestores de Projeto** 📊
- **Foco**: Status, timeline, riscos, ROI, compliance
- **Tom**: Executivo, orientado a resultados
- **Formato**: Dashboards, sumários executivos, KPIs

### 📚 Governança de Conteúdo
**Princípios de gerenciamento da informação**

- **Consistência Terminológica**: Glossário único para todos os públicos
- **Versionamento Semântico**: Controle de versões por audiência
- **Localização Cultural**: Adaptação para contexto brasileiro
- **Acessibilidade**: Conformidade com diretrizes de acessibilidade
- **Multilingual Support**: Português brasileiro com termos técnicos em inglês

---

**Última Atualização**: 8 de agosto de 2025  
**Versão da Documentação**: 3.0  
**Responsável**: Equipe Monitor Legislativo v4  
**Conformidade**: ABNT, LGPD, Acessibilidade Digital  
**Categorias**: Deployment, Arquitetura, Guias, Relatórios, Operações, Legado