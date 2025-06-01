# Monitor Legislativo - Guia do Usuário

## Visão Geral

O Monitor Legislativo é uma plataforma abrangente para monitoramento e análise de atividades legislativas do governo brasileiro. Esta documentação fornece instruções detalhadas sobre como usar todas as funcionalidades do sistema.

## Índice

1. [Primeiros Passos](#primeiros-passos)
2. [Interface Principal](#interface-principal)
3. [Funcionalidades de Busca](#funcionalidades-de-busca)
4. [Sistema de Alertas](#sistema-de-alertas)
5. [Exportação de Dados](#exportação-de-dados)
6. [Monitoramento em Tempo Real](#monitoramento-em-tempo-real)
7. [Configurações da Conta](#configurações-da-conta)
8. [FAQ](#faq)
9. [Suporte Técnico](#suporte-técnico)

## Primeiros Passos

### 1. Acesso ao Sistema

1. Acesse https://monitor-legislativo.gov.br
2. Faça login com suas credenciais institucionais
3. Complete o processo de configuração inicial do perfil

### 2. Dashboard Principal

Após o login, você será direcionado ao dashboard principal que exibe:

- **Resumo de Atividades**: Estatísticas dos últimos documentos processados
- **Alertas Ativos**: Notificações de documentos que correspondem aos seus critérios
- **Atividade Recente**: Últimas ações realizadas no sistema
- **Status do Sistema**: Indicadores de saúde dos serviços

### 3. Navegação

O menu principal oferece acesso às seguintes seções:

- **🏠 Dashboard**: Página inicial com resumo geral
- **🔍 Busca**: Ferramenta de pesquisa avançada
- **🔔 Alertas**: Gerenciamento de alertas e notificações
- **📊 Relatórios**: Geração e visualização de relatórios
- **📤 Exportações**: Histórico e configuração de exportações
- **⚙️ Configurações**: Preferências da conta e sistema

## Interface Principal

### Layout Responsivo

A interface se adapta automaticamente a diferentes tamanhos de tela:

- **Desktop**: Layout completo com sidebar e painéis laterais
- **Tablet**: Sidebar retrátil com navegação otimizada
- **Mobile**: Menu hamburger com navegação vertical

### Componentes Principais

#### 1. Barra de Navegação Superior
- Logo e nome do sistema
- Barra de busca rápida
- Notificações em tempo real
- Menu do usuário

#### 2. Sidebar de Navegação
- Links para todas as seções principais
- Indicadores de status dos serviços
- Atalhos para ações frequentes

#### 3. Área de Conteúdo Principal
- Conteúdo dinâmico baseado na seção ativa
- Breadcrumbs para navegação hierárquica
- Filtros e controles contextuais

## Funcionalidades de Busca

### 1. Busca Simples

Na barra de busca principal:

1. Digite termos relacionados ao que procura
2. Pressione Enter ou clique no botão de busca
3. Os resultados são exibidos instantaneamente

**Exemplos de busca:**
- `lei proteção dados`
- `decreto transparência`
- `PL 1234/2024`

### 2. Busca Avançada

Acesse a página de busca avançada para opções mais específicas:

#### Filtros Disponíveis

**Por Tipo de Documento:**
- ☑️ Projetos de Lei (PL)
- ☑️ Decretos
- ☑️ Portarias
- ☑️ Resoluções
- ☑️ Medidas Provisórias (MP)
- ☑️ Propostas de Emenda Constitucional (PEC)

**Por Origem:**
- 🏛️ Câmara dos Deputados
- 🏛️ Senado Federal
- 🏛️ Planalto
- 🏛️ Ministérios
- 🏛️ Agências Reguladoras

**Por Período:**
- Data de publicação
- Data de última atualização
- Período personalizado

**Por Status:**
- Em tramitação
- Aprovado
- Rejeitado
- Arquivado
- Sancionado

#### Operadores de Busca

Use operadores para refinar sua pesquisa:

- **AND**: `proteção AND dados` (ambos os termos)
- **OR**: `decreto OR portaria` (qualquer um dos termos)
- **NOT**: `lei NOT revogada` (exclui termos)
- **Aspas**: `"proteção de dados"` (frase exata)
- **Asterisco**: `regul*` (busca por prefixo)

### 3. Busca por Similaridade

O sistema usa inteligência artificial para encontrar documentos similares:

1. Selecione um documento de interesse
2. Clique em "Encontrar similares"
3. O sistema retorna documentos com conteúdo relacionado

### 4. Histórico de Buscas

Suas buscas são automaticamente salvas para fácil acesso:

- Acesse o histórico no menu lateral
- Clique em uma busca anterior para repetí-la
- Favorite buscas importantes para acesso rápido

## Sistema de Alertas

### 1. Criando Alertas

Para criar um novo alerta:

1. Vá para a seção **Alertas**
2. Clique em **"Novo Alerta"**
3. Configure os critérios:

#### Configuração Básica
- **Nome do Alerta**: Identificação clara
- **Descrição**: Detalhes do que está monitorando
- **Palavras-chave**: Termos a serem monitorados
- **Frequência**: Instantâneo, Diário, Semanal

#### Critérios Avançados
- **Filtros de Tipo**: Selecione tipos específicos de documento
- **Filtros de Origem**: Escolha fontes específicas
- **Operadores Lógicos**: Use AND, OR, NOT para critérios complexos

#### Configurações de Entrega
- **E-mail**: Receba notificações por e-mail
- **WebSocket**: Notificações em tempo real na plataforma
- **Webhook**: Integração com sistemas externos

### 2. Gerenciando Alertas

Na página de gerenciamento de alertas você pode:

- **Visualizar**: Lista de todos os alertas ativos
- **Editar**: Modificar critérios e configurações
- **Pausar/Reativar**: Controlar quando receber notificações
- **Excluir**: Remover alertas desnecessários
- **Duplicar**: Criar variações de alertas existentes

### 3. Tipos de Notificação

#### Notificações Instantâneas
- Aparecem no canto superior direito
- Som opcional para alertas críticos
- Clique para ver detalhes do documento

#### Notificações por E-mail
- Resumo diário/semanal configurável
- Links diretos para documentos
- Opção de cancelar inscrição

#### Notificações Push (Mobile)
- Disponível no app móvel
- Configuração granular por tipo de alerta
- Agrupamento inteligente para evitar spam

## Exportação de Dados

### 1. Formatos Disponíveis

O sistema suporta múltiplos formatos de exportação:

#### CSV (Comma Separated Values)
- Ideal para análise em planilhas
- Campos customizáveis
- Encoding UTF-8 para caracteres especiais

#### JSON (JavaScript Object Notation)
- Formato estruturado para desenvolvedores
- Metadados completos incluídos
- Ideal para integração com APIs

#### Excel (.xlsx)
- Planilhas formatadas com múltiplas abas
- Gráficos e tabelas dinâmicas incluídas
- Compatível com Microsoft Excel e LibreOffice

#### PDF
- Relatórios formatados para impressão
- Inclui gráficos e visualizações
- Ideal para apresentações e documentação

### 2. Processo de Exportação

#### Exportação Simples
1. Realize uma busca ou aplicue filtros
2. Clique no botão **"Exportar"**
3. Selecione o formato desejado
4. Aguarde o processamento
5. Download automático quando concluído

#### Exportação Avançada
1. Acesse **Relatórios > Nova Exportação**
2. Configure parâmetros avançados:
   - **Campos personalizados**: Selecione quais dados incluir
   - **Filtros avançados**: Refine os dados exportados
   - **Agrupamento**: Organize por categorias
   - **Período**: Defina intervalo de datas

#### Exportações Agendadas
- Configure exportações automáticas
- Receba por e-mail em intervalos regulares
- Ideal para relatórios periódicos

### 3. Limites e Considerações

- **Limite por exportação**: 100.000 registros
- **Tempo de processamento**: Varia conforme o volume
- **Armazenamento**: Arquivos ficam disponíveis por 30 dias
- **Notificações**: E-mail quando a exportação estiver pronta

## Monitoramento em Tempo Real

### 1. WebSocket - Atualizações Instantâneas

O sistema usa WebSocket para atualizações em tempo real:

- **Documentos Novos**: Aparecem automaticamente nas listas
- **Status Updates**: Mudanças de status são refletidas instantaneamente
- **Alertas**: Notificações aparecem sem necessidade de recarregar

### 2. Dashboard em Tempo Real

O dashboard exibe informações atualizadas constantemente:

#### Métricas ao Vivo
- **Documentos Processados**: Contador em tempo real
- **Alertas Acionados**: Número de alertas nas últimas horas
- **Usuários Ativos**: Quantidade de usuários online
- **Performance do Sistema**: Status dos serviços

#### Gráficos Interativos
- **Timeline de Atividades**: Visualização temporal dos eventos
- **Distribuição por Tipo**: Gráfico de pizza dos tipos de documento
- **Origem dos Documentos**: Gráfico de barras por fonte
- **Tendências**: Análise de tendências ao longo do tempo

### 3. Notificações em Tempo Real

#### Central de Notificações
- Acesse clicando no ícone de sino (🔔)
- Histórico das últimas 100 notificações
- Filtros por tipo e importância
- Marcar como lida/não lida

#### Tipos de Notificação em Tempo Real
- **🆕 Novo Documento**: Documento corresponde aos seus alertas
- **📝 Atualização**: Documento monitorado foi atualizado
- **⚠️ Sistema**: Avisos sobre manutenção ou problemas
- **✅ Processamento**: Confirmação de exportações e relatórios

## Configurações da Conta

### 1. Perfil do Usuário

Acesse **Configurações > Perfil** para gerenciar:

#### Informações Pessoais
- Nome completo
- E-mail de contato
- Telefone (opcional)
- Foto do perfil

#### Configurações de Preferência
- **Idioma**: Português (BR) ou Inglês
- **Fuso Horário**: Configuração automática por localização
- **Tema**: Claro, Escuro ou Automático
- **Densidade**: Compacto ou Espaçado

### 2. Notificações

Configure como e quando receber notificações:

#### E-mail
- **Alertas Instantâneos**: Sim/Não
- **Resumo Diário**: Horário preferido
- **Resumo Semanal**: Dia da semana preferido
- **Atualizações do Sistema**: Manutenções e novidades

#### Navegador
- **Notificações Push**: Permitir/Bloquear
- **Sons**: Habilitar sons para alertas
- **Badges**: Mostrar contadores nas abas

#### Mobile (se aplicável)
- **Notificações Push**: Configuração por tipo
- **Horário Silencioso**: Definir período sem notificações
- **Vibração**: Habilitar/Desabilitar

### 3. Segurança

#### Alteração de Senha
1. Acesse **Configurações > Segurança**
2. Clique em **"Alterar Senha"**
3. Insira a senha atual
4. Defina nova senha (mínimo 8 caracteres)
5. Confirme a nova senha

#### Autenticação em Duas Etapas (2FA)
1. Baixe um app autenticador (Google Authenticator, Authy)
2. Escaneie o QR Code fornecido
3. Insira o código de 6 dígitos
4. Salve os códigos de backup em local seguro

#### Sessões Ativas
- Visualize dispositivos conectados
- Encerre sessões remotamente
- Monitore atividade de login

### 4. Integração com APIs

Para desenvolvedores e integrações:

#### Tokens de API
1. Acesse **Configurações > API**
2. Clique em **"Gerar Token"**
3. Defina permissões e validade
4. Copie o token (não será exibido novamente)

#### Webhooks
- Configure URLs para receber notificações
- Teste conectividade com ping
- Monitore entregas e falhas

## FAQ - Perguntas Frequentes

### Funcionalidades Gerais

**P: Como posso buscar por número específico de projeto de lei?**
R: Use o formato "PL 1234/2024" na busca simples ou use o filtro "Número do Documento" na busca avançada.

**P: É possível exportar apenas os campos que me interessam?**
R: Sim, na exportação avançada você pode selecionar quais campos incluir no arquivo final.

**P: As notificações funcionam em tempo real?**
R: Sim, o sistema usa WebSocket para atualizações instantâneas quando você está online.

**P: Posso compartilhar meus alertas com outros usuários?**
R: Atualmente não, mas esta funcionalidade está planejada para uma versão futura.

### Problemas Técnicos

**P: A página não carrega ou fica lenta**
R: Verifique sua conexão de internet. Se o problema persistir, entre em contato com o suporte técnico.

**P: Não estou recebendo notificações por e-mail**
R: Verifique sua pasta de spam e confirme se o e-mail está correto nas configurações.

**P: A busca não retorna resultados esperados**
R: Tente usar sinônimos ou termos mais amplos. Use a busca avançada para filtros específicos.

**P: Minha exportação falhou**
R: Exportações com muitos dados podem demorar. Verifique o histórico de exportações ou tente com filtros mais restritivos.

### Conta e Segurança

**P: Esqueci minha senha**
R: Use a opção "Esqueci minha senha" na tela de login para receber um link de redefinição.

**P: Como posso aumentar a segurança da minha conta?**
R: Ative a autenticação em duas etapas e use uma senha forte com pelo menos 12 caracteres.

**P: Posso acessar de múltiplos dispositivos?**
R: Sim, você pode acessar de qualquer dispositivo. Monitore as sessões ativas nas configurações de segurança.

## Suporte Técnico

### Canais de Atendimento

#### Portal de Suporte
- **URL**: https://suporte.monitor-legislativo.gov.br
- **Horário**: 24/7 (portal online)
- **Recursos**: Base de conhecimento, tutoriais em vídeo, FAQ

#### E-mail
- **Geral**: suporte@monitor-legislativo.gov.br
- **Técnico**: tech@monitor-legislativo.gov.br
- **Tempo de resposta**: 24 horas úteis

#### Telefone
- **Número**: 0800-123-4567
- **Horário**: Segunda a sexta, 8h às 18h
- **Atendimento**: Português

#### Chat Online
- **Disponível**: Segunda a sexta, 8h às 18h
- **Acesso**: Botão no canto inferior direito da tela
- **Idiomas**: Português e Inglês

### Informações para Contato

Quando entrar em contato, tenha em mãos:

1. **Usuário/E-mail**: Sua identificação no sistema
2. **Navegador**: Chrome, Firefox, Safari, etc. e versão
3. **Sistema Operacional**: Windows, macOS, Linux
4. **Descrição Detalhada**: O que você estava fazendo quando o problema ocorreu
5. **Mensagens de Erro**: Copie exatamente qualquer mensagem exibida
6. **Screenshots**: Se possível, inclua imagens do problema

### Status do Sistema

Verifique o status dos serviços em tempo real:

- **URL**: https://status.monitor-legislativo.gov.br
- **Atualizações**: Tempo real
- **Histórico**: Últimos 90 dias de disponibilidade
- **Notificações**: Inscreva-se para receber atualizações de manutenção

### Relatório de Bugs

Para reportar problemas técnicos:

1. Acesse o portal de suporte
2. Escolha "Reportar Bug"
3. Preencha todas as informações solicitadas
4. Inclua screenshots ou vídeos se possível
5. Aguarde confirmação de recebimento

---

**Versão do Documento**: 1.0  
**Última Atualização**: Janeiro 2025  
**Próxima Revisão**: Abril 2025

Para sugestões de melhoria nesta documentação, entre em contato: docs@monitor-legislativo.gov.br