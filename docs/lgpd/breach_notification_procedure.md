# Procedimento de Notificação de Incidentes de Segurança
# Monitor Legislativo v4

**Data de Criação:** 21 de Novembro de 2025
**Versão:** 1.0
**Responsável:** Universidade Presbiteriana Mackenzie
**Base Legal:** LGPD Art. 48 (Lei nº 13.709/2018)

---

## 1. OBJETIVO

Este documento estabelece o procedimento obrigatório para **detecção, avaliação, contenção e notificação** de incidentes de segurança que envolvam dados pessoais, em conformidade com a LGPD Art. 48.

---

## 2. BASE LEGAL

### LGPD Art. 48 - Comunicação de Incidente de Segurança

> "O controlador deverá comunicar à autoridade nacional e ao titular a ocorrência de incidente de segurança que possa acarretar risco ou dano relevante aos titulares."

**Prazo:** Comunicação em prazo razoável (interpretação: **até 72 horas** conforme boas práticas internacionais e GDPR)

**Conteúdo Mínimo da Notificação:**
- I - Descrição da natureza dos dados pessoais afetados
- II - Informações sobre os titulares envolvidos
- III - Indicação das medidas técnicas e de segurança utilizadas para proteção
- IV - Riscos relacionados ao incidente
- V - Motivos da demora (se aplicável)
- VI - Medidas adotadas para reverter ou mitigar os efeitos

---

## 3. DEFINIÇÕES

### 3.1 Incidente de Segurança
Qualquer evento confirmado ou suspeito que comprometa:
- **Confidencialidade:** Acesso não autorizado a dados pessoais
- **Integridade:** Modificação ou corrupção não autorizada de dados
- **Disponibilidade:** Perda de acesso ou indisponibilidade de dados

### 3.2 Dados Pessoais Afetados (Monitor Legislativo v4)
- Endereços IP de usuários
- Logs de pesquisa e navegação
- Session IDs e cookies
- Preferências de usuário
- Dados de consentimento

### 3.3 Severidade dos Incidentes

| Nível | Descrição | Exemplos | Ação |
|-------|-----------|----------|------|
| **CRÍTICO** | Risco alto e imediato | Vazamento massivo de dados, ransomware | Notificação obrigatória ANPD + Titulares |
| **ALTO** | Risco significativo | Acesso não autorizado a logs, brecha de segurança | Notificação obrigatória ANPD |
| **MÉDIO** | Risco moderado | Tentativa de ataque bloqueada, vulnerabilidade descoberta | Registro interno, análise |
| **BAIXO** | Risco mínimo | Falha temporária, erro de configuração | Registro interno |

---

## 4. EQUIPE DE RESPOSTA A INCIDENTES

### 4.1 Composição da Equipe

| Função | Responsável | Contato |
|--------|-------------|---------|
| **Coordenador** | Encarregado de Proteção de Dados (DPO) | dpo@mackenzie.br |
| **Técnico Principal** | Administrador de Sistemas | Ti-sistemas@mackenzie.br |
| **Jurídico** | Assessoria Jurídica Mackenzie | juridico@mackenzie.br |
| **Comunicação** | Assessoria de Imprensa | imprensa@mackenzie.br |
| **Gestão** | Diretor de TI | ti-diretoria@mackenzie.br |

### 4.2 Responsabilidades

**DPO (Coordenador):**
- Liderança da resposta ao incidente
- Comunicação com ANPD
- Documentação e relatórios
- Interface com titulares afetados

**Equipe Técnica:**
- Detecção e análise do incidente
- Contenção e recuperação
- Investigação forense
- Implementação de correções

**Jurídico:**
- Avaliação de implicações legais
- Suporte em comunicações oficiais
- Interface com autoridades

**Comunicação:**
- Preparação de comunicados
- Gestão de imprensa (se necessário)
- Transparência pública

---

## 5. PROCEDIMENTO DE RESPOSTA

### FASE 1: DETECÇÃO E TRIAGEM (0-2 horas)

#### 5.1 Canais de Detecção
- Sistema de monitoramento automatizado
- Alertas de segurança (logs, IDS/IPS)
- Relatórios de usuários
- Auditoria periódica
- Notificação de terceiros (pesquisadores de segurança)

#### 5.2 Primeira Resposta
1. **Registrar o incidente** (timestamp, fonte, descrição inicial)
2. **Notificar o DPO imediatamente**
3. **Ativar a equipe de resposta**
4. **Preservar evidências** (logs, capturas de tela, snapshots)

#### 5.3 Triagem Inicial
**Checklist:**
- [ ] Incidente confirmado ou suspeito?
- [ ] Dados pessoais estão envolvidos?
- [ ] Qual a severidade preliminar?
- [ ] Há risco imediato aos titulares?
- [ ] Incidente está contido?

---

### FASE 2: AVALIAÇÃO E CLASSIFICAÇÃO (2-6 horas)

#### 5.4 Análise Detalhada

**Investigar:**
1. **Natureza do Incidente**
   - Tipo: Acesso não autorizado, vazamento, perda, ransomware, DDoS, etc.
   - Vetor de ataque: SQL injection, phishing, malware, erro humano, etc.
   - Momento: Quando ocorreu? Quando foi detectado?

2. **Dados Afetados**
   - Tipos de dados pessoais comprometidos
   - Quantidade de registros
   - Sensibilidade dos dados
   - Período dos dados (histórico ou atual)

3. **Titulares Impactados**
   - Número de titulares afetados
   - Categorias de titulares (pesquisadores, estudantes, público geral)
   - Possibilidade de identificação dos titulares

4. **Causas Raiz**
   - Vulnerabilidade técnica explorada
   - Falha de processo ou controle
   - Erro humano ou negligência
   - Ataque direcionado ou oportunista

#### 5.5 Classificação de Severidade

**Matriz de Risco:**

| Impacto / Probabilidade | Baixa | Média | Alta |
|------------------------|-------|-------|------|
| **Baixo** | BAIXO | BAIXO | MÉDIO |
| **Médio** | BAIXO | MÉDIO | ALTO |
| **Alto** | MÉDIO | ALTO | CRÍTICO |

**Fatores de Impacto:**
- Volume de dados comprometidos
- Sensibilidade dos dados
- Possibilidade de identificação dos titulares
- Potencial para dano material ou moral

**Fatores de Probabilidade:**
- Dados foram exfiltrados?
- Dados foram publicados?
- Há evidência de uso malicioso?

---

### FASE 3: CONTENÇÃO E ERRADICAÇÃO (6-24 horas)

#### 5.6 Contenção Imediata
**Ações emergenciais:**
- [ ] Isolar sistemas comprometidos
- [ ] Bloquear acessos não autorizados
- [ ] Revogar credenciais comprometidas
- [ ] Desativar funcionalidades vulneráveis
- [ ] Implementar regras de firewall temporárias
- [ ] Preservar evidências forenses

#### 5.7 Erradicação
- Remover malware ou backdoors
- Corrigir vulnerabilidades exploradas
- Aplicar patches de segurança
- Revisar configurações de segurança
- Validar integridade dos sistemas

#### 5.8 Recuperação
- Restaurar sistemas a partir de backups confiáveis
- Verificar integridade dos dados restaurados
- Reativar funcionalidades gradualmente
- Monitoramento intensivo pós-recuperação

---

### FASE 4: NOTIFICAÇÃO (24-72 horas)

#### 5.9 Decisão de Notificação

**Notificação OBRIGATÓRIA à ANPD se:**
- Incidente pode acarretar risco ou dano relevante aos titulares
- Dados pessoais foram acessados, alterados ou exfiltrados
- Severidade: ALTO ou CRÍTICO

**Notificação OBRIGATÓRIA aos TITULARES se:**
- Risco alto de dano material ou moral
- Medidas de proteção podem ser tomadas pelos titulares
- Severidade: CRÍTICO

#### 5.10 Comunicação à ANPD

**Canal:** https://www.gov.br/anpd/pt-br/canais_atendimento/comunicacao-de-incidente
**Prazo:** Até 72 horas após confirmação do incidente
**Responsável:** DPO

**Conteúdo da Notificação:**
1. **Identificação do Controlador**
   - Nome: Universidade Presbiteriana Mackenzie
   - CNPJ: 60.967.551/0001-01
   - DPO: dpo@mackenzie.br

2. **Descrição do Incidente**
   - Data e hora de ocorrência
   - Data e hora de detecção
   - Tipo de incidente
   - Vetor de ataque

3. **Dados Pessoais Afetados (LGPD Art. 48, I)**
   - Tipos de dados: [IP, logs de pesquisa, session IDs, etc.]
   - Volume estimado: [número de registros]
   - Período dos dados: [datas]

4. **Titulares Envolvidos (LGPD Art. 48, II)**
   - Número de titulares afetados: [estimativa]
   - Categorias de titulares: [pesquisadores, estudantes, etc.]

5. **Medidas de Segurança (LGPD Art. 48, III)**
   - Criptografia: TLS 1.3, AES-256
   - Controles de acesso: [descrever]
   - Outras medidas: [listar]

6. **Riscos Relacionados (LGPD Art. 48, IV)**
   - Risco de identificação de usuários: [avaliar]
   - Risco de uso malicioso: [avaliar]
   - Potencial para dano: [descrever]

7. **Medidas Adotadas (LGPD Art. 48, VI)**
   - Contenção: [descrever ações]
   - Erradicação: [descrever correções]
   - Mitigação de impacto: [descrever medidas]

8. **Motivos de Demora (LGPD Art. 48, V - se aplicável)**
   - Justificativa caso notificação > 72h

#### 5.11 Comunicação aos Titulares

**Métodos:**
- Notificação no aplicativo (banner visível)
- E-mail (se dados de contato disponíveis)
- Publicação na página principal
- Assessoria de imprensa (casos graves)

**Conteúdo da Comunicação:**
```
ASSUNTO: Notificação de Incidente de Segurança - Monitor Legislativo

Prezado(a) Usuário(a),

Informamos que em [DATA], identificamos um incidente de segurança
em nosso sistema Monitor Legislativo que pode ter afetado seus dados.

DADOS AFETADOS:
[Descrever tipos de dados comprometidos]

AÇÃO RECOMENDADA:
[Instruções específicas para o titular]

MEDIDAS TOMADAS:
[Resumo das correções implementadas]

CONTATO:
Para mais informações, contate nosso DPO:
E-mail: dpo@mackenzie.br
Telefone: +55 (11) 2114-8000

Pedimos desculpas pelo ocorrido e reiteramos nosso compromisso
com a proteção de seus dados.

Atenciosamente,
Universidade Presbiteriana Mackenzie
```

---

### FASE 5: PÓS-INCIDENTE (Após Resolução)

#### 5.12 Análise Pós-Incidente

**Relatório Final (7 dias após resolução):**
1. **Resumo Executivo**
   - Linha do tempo completa
   - Impacto final quantificado
   - Lições aprendidas

2. **Análise Técnica**
   - Causa raiz detalhada
   - Vulnerabilidades exploradas
   - Falhas de controle identificadas

3. **Ações Corretivas**
   - Correções implementadas
   - Melhorias de segurança
   - Atualizações de procedimentos

4. **Recomendações**
   - Investimentos em segurança
   - Treinamentos necessários
   - Revisão de políticas

#### 5.13 Ações de Melhoria

**Implementar:**
- [ ] Patches de segurança adicionais
- [ ] Controles preventivos
- [ ] Monitoramento aprimorado
- [ ] Treinamento da equipe
- [ ] Atualização de políticas
- [ ] Testes de penetração
- [ ] Revisão de DPIAs

#### 5.14 Documentação e Arquivo
- Todos os registros arquivados por **5 anos**
- Evidências preservadas para investigação
- Relatórios disponíveis para ANPD mediante requisição

---

## 6. TEMPLATES E FORMULÁRIOS

### 6.1 Registro Inicial de Incidente

```
DATA/HORA DE DETECÇÃO: _________________
DETECTADO POR: _________________________
CANAL DE DETECÇÃO: _____________________

DESCRIÇÃO INICIAL:
_____________________________________________
_____________________________________________

DADOS PESSOAIS ENVOLVIDOS? [ ] SIM [ ] NÃO
SEVERIDADE PRELIMINAR: [ ] BAIXO [ ] MÉDIO [ ] ALTO [ ] CRÍTICO

DPO NOTIFICADO? [ ] SIM - HORA: ____
EQUIPE ATIVADA? [ ] SIM - HORA: ____

PRIMEIRA AÇÃO TOMADA:
_____________________________________________
```

### 6.2 Checklist de Notificação à ANPD

- [ ] Incidente confirmado e classificado
- [ ] Severidade: ALTO ou CRÍTICO
- [ ] Dados pessoais comprometidos
- [ ] Prazo de 72h não expirado
- [ ] Relatório técnico completo
- [ ] Aprovação do DPO
- [ ] Formulário ANPD preenchido
- [ ] Comprovante de envio arquivado
- [ ] Titulares notificados (se necessário)

---

## 7. CONTATOS DE EMERGÊNCIA

### 7.1 Internos
- **DPO:** dpo@mackenzie.br | +55 (11) 2114-8000
- **TI Segurança:** ti-seguranca@mackenzie.br
- **Jurídico:** juridico@mackenzie.br
- **Reitoria:** reitoria@mackenzie.br

### 7.2 Externos
- **ANPD:** https://www.gov.br/anpd/ | contato@anpd.gov.br
- **CERT.br:** https://www.cert.br/ | cert@cert.br
- **Polícia Federal - DELECIBER:** deleciber@pf.gov.br

---

## 8. TREINAMENTO E SIMULAÇÕES

### 8.1 Treinamento Obrigatório
- **Frequência:** Anual
- **Público:** Equipe técnica, DPO, gestores
- **Conteúdo:** Procedimentos de resposta, notificação, LGPD

### 8.2 Exercícios de Simulação
- **Frequência:** Semestral
- **Tipo:** Tabletop exercises (cenários hipotéticos)
- **Objetivo:** Testar e refinar procedimentos

---

## 9. ATUALIZAÇÕES DESTE PROCEDIMENTO

| Versão | Data | Alterações | Aprovado por |
|--------|------|------------|--------------|
| 1.0 | 21/11/2025 | Criação do procedimento | DPO Mackenzie |

**Próxima Revisão:** Maio de 2026 ou após incidente significativo

---

## 10. APROVAÇÃO

Este procedimento foi aprovado pela Reitoria da Universidade Presbiteriana Mackenzie e está em conformidade com a LGPD Art. 48.

**Responsável:** Encarregado de Proteção de Dados (DPO)
**E-mail:** dpo@mackenzie.br
**Data:** 21 de Novembro de 2025

---

**IMPORTANTE:** Este procedimento deve ser conhecido por todos os membros da equipe técnica e gestores responsáveis pela proteção de dados pessoais.
