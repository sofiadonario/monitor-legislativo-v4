# Monitor de Políticas Públicas MackIntegridade v4

Sistema integrado de monitoramento legislativo brasileiro com suporte para múltiplas fontes governamentais e agências reguladoras.

## 🚀 Novidades da Versão 4.0

- ✅ **Arquitetura modular** com núcleo compartilhado entre desktop e web
- ✅ **Correções de API** baseadas em relatório de erros detalhado
- ✅ **Integração com Agências Reguladoras** (ANEEL, ANATEL, ANVISA, ANS, ANA, etc.)
- ✅ **Melhor tratamento de erros** com retry automático e fallbacks
- ✅ **Cache inteligente** para melhor performance
- ✅ **Novos formatos de exportação** (JSON, XLSX)
- ✅ **Suporte para Playwright** para scraping de conteúdo JavaScript

## 📋 Características

### Fontes de Dados

#### Governo Federal
- **Câmara dos Deputados**: API oficial com fallback para web scraping
- **Senado Federal**: API XML com busca fuzzy aprimorada
- **Diário Oficial da União**: Scraping com Playwright para conteúdo dinâmico

#### Agências Reguladoras
- ANEEL - Agência Nacional de Energia Elétrica
- ANATEL - Agência Nacional de Telecomunicações  
- ANVISA - Agência Nacional de Vigilância Sanitária
- ANS - Agência Nacional de Saúde Suplementar
- ANA - Agência Nacional de Águas
- ANCINE - Agência Nacional do Cinema
- ANTT - Agência Nacional de Transportes Terrestres
- ANTAQ - Agência Nacional de Transportes Aquaviários
- ANAC - Agência Nacional de Aviação Civil
- ANP - Agência Nacional do Petróleo
- ANM - Agência Nacional de Mineração

### Funcionalidades

- 🔍 **Busca unificada** em múltiplas fontes simultaneamente
- 📅 **Filtros avançados** por data, tipo e fonte
- 📊 **Exportação** em CSV, HTML, PDF, JSON e Excel
- 🚦 **Monitoramento de status** das APIs em tempo real
- 💾 **Cache inteligente** para otimizar performance
- 🌐 **Versões desktop e web** (web em desenvolvimento)

## 🛠️ Instalação

### Requisitos
- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/mackintegridade/monitor-legislativo-v4.git
cd monitor-legislativo-v4

# Instale as dependências
pip install -r requirements.txt

# Instale o Playwright (para scraping do Diário Oficial)
playwright install chromium
```

### Instalação Completa

```bash
# Instalação via setup.py
python setup.py install

# Ou instalação em modo desenvolvimento
pip install -e .
```

## 🚀 Uso

### Versão Desktop

```bash
# Executar diretamente
python -m desktop.main

# Ou após instalação
monitor-legislativo
```

### Versão Web (Em desenvolvimento)

```bash
# Executar servidor
python -m web.main

# Ou após instalação
monitor-legislativo-web
```

## 🔧 Configuração

O sistema utiliza configurações padrão otimizadas, mas você pode personalizar em `core/config/config.py`:

- Timeouts de API
- Limites de cache
- Habilitação de fontes específicas
- Configurações de retry

## 📖 Documentação da API

### Exemplo de Uso Programático

```python
from core.api import APIService
from core.models import SearchFilters
from datetime import datetime, timedelta

# Inicializar serviço
api_service = APIService()

# Configurar filtros
filters = {
    "start_date": (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d"),
    "end_date": datetime.now().strftime("%Y-%m-%d")
}

# Buscar em todas as fontes
results = await api_service.search_all(
    query="meio ambiente",
    filters=filters,
    sources=["camara", "senado", "planalto", "aneel"]
)

# Processar resultados
for result in results:
    print(f"\n{result.source.value}: {result.total_count} resultados")
    for prop in result.propositions[:5]:
        print(f"- {prop.formatted_number}: {prop.title}")
```

## 🧪 Testes

```bash
# Executar todos os testes
pytest

# Testes com cobertura
pytest --cov=core tests/

# Testes específicos
pytest tests/test_api_services.py
```

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📝 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🏢 Sobre o MackIntegridade

O MackIntegridade é um centro de pesquisa dedicado ao estudo e promoção da integridade, transparência e combate à corrupção. Este monitor legislativo é uma ferramenta desenvolvida para auxiliar pesquisadores e a sociedade civil no acompanhamento de políticas públicas relacionadas à sustentabilidade e meio ambiente.

## 📞 Contato

- Website: [www.mackintegridade.org](https://www.mackintegridade.org)
- Email: contato@mackintegridade.org

## 🙏 Agradecimentos

- Câmara dos Deputados pelo acesso à API de dados abertos
- Senado Federal pela disponibilização de dados legislativos
- Comunidade open source pelos excelentes frameworks e bibliotecas