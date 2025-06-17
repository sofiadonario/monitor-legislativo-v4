# Academic Legislative Monitor - Transport Research

An academic research platform for monitoring Brazilian transport legislation using real government data.

## 🎯 Overview

This academic tool provides researchers with access to comprehensive transport legislation data from Brazilian government sources. It includes both web-based visualization and R-based analysis tools designed specifically for academic research.

## 📱 Multiple Applications Available

### 🌐 **React/TypeScript Web Application** (Main Directory)
Modern frontend application with interactive maps and export capabilities.

### 🔬 **R Shiny Applications** 
- **Main R App**: `legislative_monitor_r/` - Full academic research tool with real data
- **Alternative R App**: `r-shiny-app/` - Complete implementation with authentication (admin/admin123)

### 🔍 **Transport Research Tools**
- Custom search scripts for transport legislation
- Direct API access to Brazilian government sources
- Specialized transport terms database

👉 **For academic research, use the R Shiny applications for real data access**

## ✨ Features

### 🗺️ Interactive Visualization
- Geographic mapping of transport legislation by Brazilian states
- Real-time filtering by location, type, period, and keywords
- Export capabilities in academic formats (CSV, XML, HTML)
- Properly formatted reports with academic citations

### 📊 Data Sources
All data obtained directly from official Brazilian government APIs:
- **Câmara dos Deputados API**: Chamber of Deputies data
- **Senado Federal API**: Federal Senate information  
- **LexML Brasil**: Legal XML repository
- **IBGE Geographic Data**: Official state mapping data

### 🔍 Transport-Specific Research
- Specialized search terms for transport legislation
- Monitoring of key regulatory agencies (ANTT, CONTRAN)
- Tracking of transport programs (Rota 2030)
- Historical legislation analysis

## 🛠️ Technologies

### Web Application Stack
- **React 18** - Modern frontend framework
- **TypeScript** - Static typing for reliability
- **Leaflet** - Interactive mapping
- **React-Leaflet** - React components for maps
- **PapaParse** - CSV processing for exports
- **Vite** - Fast development and build tool

### R Applications Stack  
- **R Shiny** - Interactive web applications
- **SQLite** - Lightweight database for caching
- **leaflet (R)** - Mapping in R
- **DT** - Interactive data tables
- **httr** - HTTP client for API calls

## 📦 Instalação

### Pré-requisitos
- Node.js 16+ 
- npm ou yarn

### Passos de Instalação

1. **Clone ou copie os arquivos do projeto**
```bash
# Se usando git
git clone [repository-url]
cd academic-map-app

# Ou copie todos os arquivos para uma pasta local
```

2. **Instale as dependências**
```bash
npm install
```

3. **Inicie o servidor de desenvolvimento**
```bash
npm run dev
```

4. **Acesse a aplicação**
```
http://localhost:3000
```

## 🏗️ Estrutura do Projeto

```
academic-map-app/
├── public/
│   └── index.html
├── src/
│   ├── components/          # Componentes React
│   │   ├── Dashboard.tsx    # Layout principal
│   │   ├── Map.tsx         # Componente do mapa
│   │   ├── Sidebar.tsx     # Barra lateral com filtros
│   │   └── ExportPanel.tsx # Painel de exportação
│   ├── data/               # Dados e mocks
│   │   ├── brazil-states.ts
│   │   └── mock-legislative-data.ts
│   ├── types/              # Definições TypeScript
│   │   └── index.ts
│   ├── utils/              # Utilitários
│   │   └── exportHelpers.ts
│   ├── styles/             # Estilos CSS
│   │   └── globals.css
│   ├── App.tsx             # Componente raiz
│   └── main.tsx           # Ponto de entrada
├── package.json
├── tsconfig.json
├── vite.config.ts
└── README.md
```

## 📋 Funcionalidades

### 🗺️ Mapa Interativo
- Visualização do Brasil por estados
- Clique em estados para ver detalhes
- Cores diferenciadas para estados com legislação
- Tooltips informativos

### 🔍 Sistema de Busca e Filtros
- Busca por texto livre
- Filtro por período (data inicial/final)
- Filtro por tipo de documento (lei, decreto, etc.)
- Seleção de estados específicos

### 📊 Exportação de Dados
- **CSV**: Para análise em planilhas
- **XML**: Para sistemas e APIs
- **HTML**: Relatórios formatados para leitura
- **PNG**: Imagens do mapa (planejado)

### 📱 Design Responsivo
- Interface adaptável para desktop e mobile
- Sidebar colapsável
- Navegação por teclado
- Suporte a alto contraste

## 🎓 Uso Acadêmico

### Citação dos Dados
Todos os documentos incluem:
- Citação acadêmica completa
- Fonte original
- URL quando disponível
- Data de acesso

### Sugestão de Citação da Aplicação
```
Mapa Legislativo Acadêmico. Dados legislativos georeferenciados do Brasil. 
Exportado em [DATA]. Disponível em: [URL da aplicação].
```

### Formato de Exportação HTML
Os relatórios HTML incluem:
- Cabeçalho com metadata
- Documentos formatados com citações
- Palavras-chave organizadas
- Rodapé com informações de citação

## 🛠️ Desenvolvimento

### Scripts Disponíveis

```bash
# Desenvolvimento
npm run dev

# Build para produção
npm run build

# Preview da build
npm run preview

# Análise de código
npm run lint
```

### Adicionando Novos Dados

1. **Dados de Estados**: Edite `src/data/brazil-states.ts`
2. **Dados Legislativos**: Edite `src/data/mock-legislative-data.ts`
3. **Tipos**: Atualize `src/types/index.ts` se necessário

### Personalizações

- **Cores**: Edite as variáveis CSS em `globals.css`
- **Mapas**: Substitua `brazil-states.ts` por GeoJSON completo
- **Exportação**: Estenda `exportHelpers.ts` para novos formatos

## 🔧 Configuração Avançada

### Dados Reais do GeoJSON
Para usar dados geográficos reais:

1. Baixe GeoJSON dos estados brasileiros
2. Substitua o conteúdo de `brazil-states.ts`
3. Ajuste a propriedade `coordinates` se necessário

### Integração com APIs
Para conectar com APIs reais:

1. Crie um serviço em `src/services/`
2. Substitua os dados mock
3. Adicione estados de loading

### Banco de Dados
Para persistência:

1. Configure backend (Node.js, Python, etc.)
2. Crie endpoints para CRUD
3. Substitua dados mock por chamadas de API

## 🚀 Deploy

### Opções de Deploy
- **Netlify**: `npm run build` + upload da pasta `dist`
- **Vercel**: Deploy direto do repositório
- **GitHub Pages**: Configure GitHub Actions
- **Servidor próprio**: Upload da pasta `dist`

### Variáveis de Ambiente
Crie `.env` para configurações:
```env
VITE_API_URL=https://api.exemplo.com
VITE_MAP_TOKEN=seu_token_mapbox
```

## 📝 Limitações Conhecidas

1. **Dados Mock**: Atualmente usa dados simulados
2. **GeoJSON Simplificado**: Coordenadas aproximadas dos estados
3. **Export PNG**: Funcionalidade planejada, não implementada
4. **Municípios**: Estrutura preparada, mas dados não incluídos

## 🤝 Contribuição

### Para Desenvolvedores Universitários

1. Fork o projeto
2. Crie uma branch para sua feature
3. Implemente seguindo os padrões existentes
4. Teste em diferentes dispositivos
5. Submeta um Pull Request

### Padrões de Código
- Use TypeScript para tipagem
- Siga as convenções do ESLint
- Documente funções complexas
- Mantenha responsividade
- Teste acessibilidade

## 📞 Suporte

Para questões técnicas ou sugestões:
1. Abra uma issue no repositório
2. Inclua detalhes do erro
3. Mencione o navegador e sistema operacional
4. Adicione screenshots se relevante

## 📄 Licença

Este projeto é desenvolvido para fins educacionais e de pesquisa acadêmica.

---

**Nota**: Esta aplicação foi desenvolvida como ferramenta de pesquisa acadêmica. Sempre verifique as fontes originais dos documentos legislativos antes de usar em trabalhos acadêmicos.