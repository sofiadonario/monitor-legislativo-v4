# Registro de Atividades de Tratamento de Dados Pessoais
# Monitor Legislativo v4

**Data de Criação:** 21 de Novembro de 2025
**Versão:** 1.0
**Responsável:** Universidade Presbiteriana Mackenzie
**Base Legal:** LGPD Art. 37 (Lei nº 13.709/2018)

---

## 1. IDENTIFICAÇÃO DO CONTROLADOR

### Controlador de Dados
- **Nome:** Universidade Presbiteriana Mackenzie
- **CNPJ:** 60.967.551/0001-01
- **Endereço:** Rua da Consolação, 930 - Consolação, São Paulo - SP, CEP 01302-907
- **Telefone:** +55 (11) 2114-8000
- **Website:** https://www.mackenzie.br

### Encarregado de Proteção de Dados (DPO)
- **Nome:** [A designar conforme Art. 41º LGPD]
- **E-mail:** dpo@mackenzie.br
- **Telefone:** +55 (11) 2114-8000
- **Função:** Responsável pela conformidade com LGPD e canal de comunicação com ANPD

---

## 2. ATIVIDADES DE TRATAMENTO DE DADOS

### Atividade 001: Pesquisa de Documentos Legislativos

#### 2.1 Identificação
- **ID da Atividade:** ACT-001
- **Nome:** Sistema de Pesquisa e Consulta de Documentos Legislativos
- **Sistema:** Monitor Legislativo v4
- **Ambiente:** Produção (Google Cloud Run / Railway)

#### 2.2 Finalidade do Tratamento
**Finalidade Principal:**
- Pesquisa acadêmica sobre legislação brasileira
- Análise de documentos legislativos federais, estaduais e municipais
- Suporte à pesquisa científica em ciência política e direito
- Educação e formação de pesquisadores

**Finalidades Secundárias:**
- Melhoria do sistema através de análise de uso
- Segurança e prevenção de fraudes
- Cumprimento de obrigações legais

#### 2.3 Base Legal (LGPD Art. 7º)
- **Principal:** Art. 7º, IV - Legítimo interesse do controlador para pesquisa acadêmica
- **Complementar:** Art. 7º, IX - Legítimo interesse quando necessário para atender aos interesses legítimos do controlador

**Justificativa do Legítimo Interesse:**
- Instituição acadêmica reconhecida pelo MEC
- Pesquisa em conformidade com diretrizes acadêmicas nacionais
- Benefício público através da democratização do acesso à legislação
- Minimização de dados - apenas dados essenciais coletados

#### 2.4 Categorias de Dados Pessoais

| Categoria | Dados Coletados | Sensível? | Justificativa |
|-----------|-----------------|-----------|---------------|
| **Dados de Navegação** | Endereço IP, User-Agent, Timestamp | Não | Segurança e análise de uso |
| **Dados de Sessão** | Session ID (temporário), Token | Não | Funcionamento técnico |
| **Dados de Pesquisa** | Termos de busca, filtros aplicados | Não | Funcionalidade do sistema |
| **Dados de Preferências** | Configurações de visualização | Não | Experiência do usuário |
| **Cookies** | Cookie de consentimento, sessão | Não | Conformidade LGPD |

**Dados NÃO Coletados:**
- Nome, CPF, RG, e-mail (usuários anônimos)
- Dados sensíveis (origem racial, política, religiosa, saúde)
- Dados biométricos
- Dados de localização precisa

#### 2.5 Categorias de Titulares
- Pesquisadores acadêmicos (professores, pós-graduandos)
- Estudantes universitários (graduação e pós-graduação)
- Usuários públicos em geral (acesso aberto)
- Operadores técnicos (manutenção do sistema)

#### 2.6 Compartilhamento de Dados

**Interno:**
- Equipe técnica do Mackenzie (manutenção)
- Pesquisadores autorizados (análise agregada)

**Externo:**
- **NÃO há compartilhamento com terceiros** para fins comerciais
- **NÃO há transferência internacional** de dados

**Exceções (Base Legal - Obrigação Legal):**
- Autoridades judiciais (mediante ordem judicial)
- ANPD (mediante requisição formal)

#### 2.7 Retenção e Eliminação

| Tipo de Dado | Período de Retenção | Motivo | Eliminação |
|--------------|---------------------|--------|------------|
| **Logs de pesquisa** | 24 meses | Análise de uso | Anonimização |
| **Logs de auditoria** | 5 anos | Obrigação legal | Exclusão segura |
| **Dados de sessão** | Até fim da sessão | Funcionalidade | Exclusão automática |
| **Preferências** | Até solicitação de exclusão | Consentimento | Exclusão a pedido |
| **Cookies** | 365 dias | Consentimento | Expiração automática |

**Após Período de Retenção:**
- **Anonimização:** Remoção de identificadores (IP, Session ID)
- **Exclusão:** Deleção permanente e irreversível
- **Backup:** Backups anonimizados após 36 meses

#### 2.8 Medidas de Segurança (LGPD Art. 46)

**Medidas Técnicas:**
1. **Criptografia**
   - TLS 1.3 para dados em trânsito
   - AES-256 para dados em repouso
   - Certificados SSL/TLS válidos

2. **Controle de Acesso**
   - Autenticação baseada em sessão
   - Tokens criptográficos
   - Permissões baseadas em função (RBAC)

3. **Proteção contra Ataques**
   - Proteção SQL injection (consultas parametrizadas)
   - Proteção XSS (validação e sanitização de entrada)
   - Proteção CSRF (tokens CSRF)
   - Cabeçalhos de segurança (CSP, X-Frame-Options)

4. **Auditoria**
   - Logs de acesso a dados pessoais
   - Rastreamento de modificações
   - Monitoramento de anomalias

5. **Backup e Recuperação**
   - Backups criptografados diários
   - Plano de recuperação de desastres
   - Testes de restauração trimestrais

**Medidas Organizacionais:**
1. **Políticas e Procedimentos**
   - Política de Privacidade publicada
   - Procedimento de resposta a incidentes
   - Política de retenção de dados

2. **Treinamento**
   - Capacitação da equipe técnica em LGPD
   - Conscientização sobre segurança de dados
   - Atualização anual obrigatória

3. **Gestão de Incidentes**
   - Plano de resposta a violação de dados
   - Notificação à ANPD em 72 horas
   - Comunicação aos titulares afetados

4. **Revisões**
   - Auditoria de segurança semestral
   - Avaliação de impacto à proteção de dados (DPIA)
   - Atualização de medidas conforme riscos

---

### Atividade 002: Sistema de Consentimento de Cookies

#### 2.1 Identificação
- **ID da Atividade:** ACT-002
- **Nome:** Gestão de Consentimento de Cookies
- **Sistema:** Monitor Legislativo v4 - Cookie Consent Banner

#### 2.2 Finalidade do Tratamento
- Registrar preferências de cookies do usuário
- Cumprir requisitos de consentimento LGPD
- Transparência no uso de tecnologias de rastreamento

#### 2.3 Base Legal
- **Art. 7º, I** - Consentimento expresso e informado do titular

#### 2.4 Categorias de Dados
- Cookie de consentimento (accepted/rejected)
- Data e hora do consentimento
- Preferências de cookies

#### 2.5 Retenção
- **Período:** 365 dias
- **Eliminação:** Expiração automática ou a pedido do usuário

#### 2.6 Medidas de Segurança
- Cookie HttpOnly quando aplicável
- Armazenamento local (navegador do usuário)
- Sem transmissão a terceiros

---

### Atividade 003: Logs de Auditoria para Conformidade

#### 2.1 Identificação
- **ID da Atividade:** ACT-003
- **Nome:** Sistema de Auditoria e Monitoramento
- **Sistema:** Monitor Legislativo v4 - Audit Logging

#### 2.2 Finalidade do Tratamento
- Conformidade com LGPD Art. 37 (registro de atividades)
- Segurança e detecção de incidentes
- Resposta a requisições da ANPD
- Investigação de acessos não autorizados

#### 2.3 Base Legal
- **Art. 7º, II** - Cumprimento de obrigação legal (LGPD Art. 37)
- **Art. 7º, IX** - Legítimo interesse (segurança)

#### 2.4 Categorias de Dados
- Endereço IP
- Timestamp (data e hora)
- Ação realizada (tipo de operação)
- Recurso acessado
- Resultado da operação (sucesso/falha)

#### 2.5 Retenção
- **Período:** 5 anos (requisito legal)
- **Eliminação:** Exclusão segura após 5 anos

#### 2.6 Acesso aos Logs
- **Autorizado:** DPO, equipe de segurança, auditores
- **Mediante solicitação:** ANPD, autoridades judiciais

---

## 3. AVALIAÇÃO DE IMPACTO À PROTEÇÃO DE DADOS (DPIA)

### 3.1 Necessidade de DPIA
**Avaliação:** ✅ **NÃO REQUERIDA** para operações atuais

**Justificativa:**
- Não há tratamento de dados sensíveis (Art. 5º, II)
- Não há tratamento em larga escala de dados pessoais identificáveis
- Sistema opera com dados mínimos e anonimização
- Baixo risco aos direitos e liberdades dos titulares

**Revisão:** Anual ou quando houver mudanças significativas

### 3.2 Quando DPIA Será Necessária
- Implementação de sistema de identificação de usuários
- Coleta de dados sensíveis
- Uso de tecnologias de monitoramento de comportamento
- Decisões automatizadas que afetem titulares

---

## 4. DIREITOS DOS TITULARES (LGPD Art. 18)

### 4.1 Canais de Atendimento
- **E-mail:** dpo@mackenzie.br
- **Telefone:** +55 (11) 2114-8000
- **Prazo de Resposta:** Até 15 dias úteis

### 4.2 Direitos Garantidos
1. ✅ Confirmação da existência de tratamento
2. ✅ Acesso aos dados
3. ✅ Correção de dados incompletos, inexatos ou desatualizados
4. ✅ Anonimização, bloqueio ou eliminação
5. ✅ Portabilidade dos dados
6. ✅ Eliminação dos dados (direito ao esquecimento)
7. ✅ Informação sobre compartilhamento
8. ✅ Informação sobre possibilidade de não fornecer consentimento
9. ✅ Revogação do consentimento

### 4.3 Procedimentos
- Solicitações registradas e rastreadas
- Verificação de identidade do solicitante
- Resposta em formato acessível
- Gratuidade na primeira solicitação

---

## 5. TRANSFERÊNCIA INTERNACIONAL DE DADOS

**Status:** ✅ **NÃO APLICÁVEL**

- Todos os dados armazenados em território brasileiro (Cloud SQL Brasil)
- Servidores hospedados em região southamerica-east1 (São Paulo)
- Sem transferência para outros países
- CDNs utilizados apenas para bibliotecas JavaScript públicas (sem dados pessoais)

---

## 6. CONFORMIDADE E AUDITORIA

### 6.1 Responsáveis
- **Controlador:** Reitor da Universidade Presbiteriana Mackenzie
- **DPO:** [Designar conforme Art. 41º]
- **Equipe Técnica:** Desenvolvedores e administradores de sistema

### 6.2 Revisões
- **Frequência:** Semestral (junho e dezembro)
- **Responsável:** DPO + Equipe Técnica
- **Documentação:** Relatório de conformidade arquivado por 5 anos

### 6.3 Incidentes de Segurança
- **Plano de Resposta:** Disponível em `breach_notification_procedure.md`
- **Notificação ANPD:** Até 72 horas após confirmação
- **Comunicação a Titulares:** Imediata se risco alto

---

## 7. ATUALIZAÇÕES DESTE REGISTRO

| Versão | Data | Alterações | Responsável |
|--------|------|------------|-------------|
| 1.0 | 21/11/2025 | Criação do registro inicial | DPO Mackenzie |

---

## 8. DECLARAÇÃO DE CONFORMIDADE

Este Registro de Atividades de Tratamento de Dados Pessoais foi elaborado em conformidade com:

- **LGPD Art. 37** - Obrigação de manter registro das operações
- **LGPD Art. 6º** - Princípios de proteção de dados
- **LGPD Art. 46** - Medidas de segurança técnicas e administrativas

**Atestamos** que as informações aqui contidas são verdadeiras e refletem as práticas atuais do Monitor Legislativo v4.

---

**Universidade Presbiteriana Mackenzie**
**Encarregado de Proteção de Dados (DPO)**
dpo@mackenzie.br

**Última Atualização:** 21 de Novembro de 2025
**Próxima Revisão:** Maio de 2026
