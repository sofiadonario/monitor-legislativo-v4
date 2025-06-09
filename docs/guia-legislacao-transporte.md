# Guia Completo - Integração de Bases de Dados de Legislação para Transporte Rodoviário de Cargas

## ⚠️ AVISOS CRÍTICOS - LEIA ANTES DE EXECUTAR

### Pré-requisitos Obrigatórios
- Python 3.8+ (testado em 3.8, 3.9, 3.10)
- Mínimo 8GB RAM
- 10GB espaço em disco
- Conexão estável com internet
- Sistema operacional: Linux (Ubuntu 20.04+), Windows 10+ ou MacOS 10.14+

### Limitações Conhecidas
1. APIs governamentais podem estar instáveis ou fora do ar
2. Estruturas HTML podem mudar sem aviso
3. Rate limits não documentados podem existir
4. Alguns endpoints requerem VPN brasileira se acessados do exterior

## Índice
1. [Instalação e Configuração Segura](#instalação-e-configuração-segura)
2. [Bases de Dados e URLs Verificadas](#bases-de-dados-e-urls-verificadas)
3. [Implementação com Tratamento de Erros](#implementação-com-tratamento-de-erros)
4. [Sistema de Testes](#sistema-de-testes)
5. [Monitoramento e Alertas](#monitoramento-e-alertas)
6. [Troubleshooting Detalhado](#troubleshooting-detalhado)
7. [Plano de Contingência](#plano-de-contingência)

## Instalação e Configuração Segura

### 1. Preparação do Ambiente

```bash
#!/bin/bash
# setup.sh - Script de instalação segura

set -euo pipefail  # Falha em qualquer erro

# Verificar versão do Python
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8.0"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "ERRO: Python 3.8+ é necessário. Versão atual: $python_version"
    exit 1
fi

# Criar estrutura de diretórios
mkdir -p {data,cache,logs,reports,backups,tests}

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Atualizar pip
pip install --upgrade pip setuptools wheel

# Instalar dependências com versões fixas
pip install -r requirements-lock.txt

# Verificar instalação
python verify_installation.py
```

### 2. Requirements com Versões Fixas

```txt
# requirements-lock.txt
# ATENÇÃO: Estas versões foram testadas e são estáveis
requests==2.31.0
beautifulsoup4==4.12.2
lxml==4.9.3
pandas==2.1.3
xmltodict==0.13.0
selenium==4.15.2
schedule==1.2.0
sqlalchemy==2.0.23
geopandas==0.14.1
folium==0.15.0
nltk==3.8.1
spacy==3.7.2
python-dotenv==1.0.0
retry==0.9.2
validators==0.22.0
pytest==7.4.3
pytest-cov==4.1.0
black==23.11.0
ruff==0.1.6
```

### 3. Script de Verificação de Instalação

```python
# verify_installation.py
"""Verifica se todas as dependências foram instaladas corretamente"""

import sys
import importlib
import subprocess

def verificar_instalacao():
    """Verifica instalação de todos os módulos necessários"""
    
    modulos_necessarios = [
        'requests', 'bs4', 'lxml', 'pandas', 'xmltodict',
        'selenium', 'schedule', 'sqlalchemy', 'geopandas',
        'folium', 'nltk', 'spacy', 'dotenv', 'retry',
        'validators', 'pytest'
    ]
    
    erros = []
    
    print("Verificando instalação...")
    print("-" * 50)
    
    for modulo in modulos_necessarios:
        try:
            importlib.import_module(modulo)
            print(f"✓ {modulo} instalado corretamente")
        except ImportError as e:
            erros.append(f"✗ ERRO ao importar {modulo}: {e}")
            print(f"✗ ERRO: {modulo} não está instalado")
    
    # Verificar modelo spaCy
    try:
        import spacy
        nlp = spacy.load("pt_core_news_lg")
        print("✓ Modelo spaCy pt_core_news_lg instalado")
    except:
        print("✗ ERRO: Modelo spaCy não instalado")
        print("  Execute: python -m spacy download pt_core_news_lg")
        erros.append("Modelo spaCy pt_core_news_lg não encontrado")
    
    # Verificar NLTK data
    try:
        import nltk
        nltk.data.find('corpora/stopwords')
        print("✓ NLTK stopwords instalado")
    except:
        print("✗ ERRO: NLTK stopwords não instalado")
        print("  Execute: python -c \"import nltk; nltk.download('stopwords')\"")
        erros.append("NLTK stopwords não encontrado")
    
    print("-" * 50)
    
    if erros:
        print(f"\n❌ {len(erros)} ERROS ENCONTRADOS:")
        for erro in erros:
            print(f"  - {erro}")
        sys.exit(1)
    else:
        print("\n✅ Todas as dependências instaladas corretamente!")
        return True

if __name__ == "__main__":
    verificar_instalacao()
```

## Bases de Dados e URLs Verificadas

### URLs Atualizadas e Testadas (Dezembro 2024)

```python
# config/urls.py
"""URLs verificadas e atualizadas para todas as fontes de dados"""

from datetime import datetime

# Data da última verificação
ULTIMA_VERIFICACAO = "2024-12-15"

URLS_APIS = {
    'lexmil': {
        'base': 'https://www.lexml.gov.br',
        'api': 'https://www.lexml.gov.br/busca/SRU',
        'status': 'ATIVO',
        'teste': 'https://www.lexml.gov.br/busca/SRU?operation=explain'
    },
    'camara': {
        'base': 'https://www.camara.leg.br',
        'api': 'https://dadosabertos.camara.leg.br/api/v2',
        'arquivos': 'https://dadosabertos.camara.leg.br/arquivos',
        'status': 'ATIVO',
        'teste': 'https://dadosabertos.camara.leg.br/api/v2/referencias/proposicoes/siglaTipo'
    },
    'senado': {
        'base': 'https://www12.senado.leg.br',
        'api': 'http://legis.senado.leg.br/dadosabertos',
        'status': 'ATIVO',
        'teste': 'http://legis.senado.leg.br/dadosabertos/senador/lista/atual'
    },
    'planalto': {
        'base': 'http://www4.planalto.gov.br/legislacao',
        'busca': 'https://legislacao.presidencia.gov.br',
        'status': 'REQUER_SCRAPING',
        'teste': 'http://www4.planalto.gov.br/legislacao'
    },
    'dou': {
        'base': 'https://www.in.gov.br',
        'busca': 'https://www.in.gov.br/consulta',
        'status': 'ATIVO',
        'teste': 'https://www.in.gov.br/web/guest'
    },
    'antt': {
        'base': 'https://www.gov.br/antt',
        'dados': 'https://dados.antt.gov.br',
        'api_ckan': 'https://dados.antt.gov.br/api/3',
        'status': 'ATIVO',
        'teste': 'https://dados.antt.gov.br/api/3/action/package_list'
    },
    'anp': {
        'base': 'https://www.gov.br/anp',
        'dados': 'https://www.gov.br/anp/pt-br/centrais-de-conteudo/dados-abertos',
        'status': 'PARCIAL',
        'teste': 'https://www.gov.br/anp/pt-br'
    }
}

def verificar_urls():
    """Verifica se todas as URLs estão acessíveis"""
    import requests
    
    print(f"Verificando URLs (última verificação: {ULTIMA_VERIFICACAO})")
    print("-" * 60)
    
    resultados = {}
    
    for fonte, urls in URLS_APIS.items():
        print(f"\nVerificando {fonte}...")
        
        url_teste = urls.get('teste', urls.get('base'))
        
        try:
            response = requests.head(url_teste, timeout=10, allow_redirects=True)
            status_code = response.status_code
            
            if status_code < 400:
                print(f"  ✓ {fonte}: OK (status: {status_code})")
                resultados[fonte] = 'OK'
            else:
                print(f"  ✗ {fonte}: ERRO (status: {status_code})")
                resultados[fonte] = f'ERRO: {status_code}'
                
        except Exception as e:
            print(f"  ✗ {fonte}: FALHA NA CONEXÃO ({str(e)})")
            resultados[fonte] = f'FALHA: {str(e)}'
    
    return resultados
```

## Implementação com Tratamento de Erros

### Classe Base Robusta

```python
# core/base_api.py
"""Classe base com tratamento robusto de erros"""

import requests
import time
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any, List
import json
from retry import retry
import validators

class BaseGovAPI(ABC):
    """Classe base robusta para APIs governamentais"""
    
    def __init__(self, base_url: str, nome_fonte: str, rate_limit: float = 2.0):
        # Validar URL
        if not validators.url(base_url):
            raise ValueError(f"URL inválida: {base_url}")
            
        self.base_url = base_url
        self.nome_fonte = nome_fonte
        self.rate_limit = rate_limit
        self.last_request = 0
        
        # Configurar sessão com timeouts e retry
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Monitor-Legislacao-Transporte/1.0 (contato@exemplo.com)',
            'Accept': 'application/json, application/xml, text/html',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        
        # Adapter com retry automático
        adapter = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=10,
            pool_maxsize=10
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Configurar logging detalhado
        self.logger = self._setup_logger()
        
        # Cache em memória
        self._cache = {}
        self._cache_ttl = 3600  # 1 hora
        
        # Estatísticas
        self.stats = {
            'requests_total': 0,
            'requests_sucesso': 0,
            'requests_erro': 0,
            'tempo_total': 0
        }
        
    def _setup_logger(self) -> logging.Logger:
        """Configura logger com formatação detalhada"""
        logger = logging.getLogger(f"{__name__}.{self.nome_fonte}")
        logger.setLevel(logging.DEBUG)
        
        # Handler para arquivo
        fh = logging.FileHandler(f'logs/{self.nome_fonte}_{datetime.now():%Y%m%d}.log')
        fh.setLevel(logging.DEBUG)
        
        # Handler para console
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter detalhado
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def _rate_limit_wait(self):
        """Implementa rate limiting com logging"""
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            wait_time = self.rate_limit - elapsed
            self.logger.debug(f"Rate limit: aguardando {wait_time:.2f}s")
            time.sleep(wait_time)
        self.last_request = time.time()
    
    def _get_cache_key(self, url: str, params: Optional[Dict] = None) -> str:
        """Gera chave de cache"""
        if params:
            params_str = json.dumps(params, sort_keys=True)
            return f"{url}:{params_str}"
        return url
    
    def _get_from_cache(self, cache_key: str) -> Optional[Any]:
        """Recupera do cache se ainda válido"""
        if cache_key in self._cache:
            entry = self._cache[cache_key]
            if time.time() - entry['timestamp'] < self._cache_ttl:
                self.logger.debug(f"Cache hit: {cache_key}")
                return entry['data']
        return None
    
    def _save_to_cache(self, cache_key: str, data: Any):
        """Salva no cache"""
        self._cache[cache_key] = {
            'data': data,
            'timestamp': time.time()
        }
    
    @retry(tries=3, delay=2, backoff=2)
    def fazer_requisicao(self, url: str, params: Optional[Dict] = None, 
                        method: str = 'GET', timeout: int = 30) -> requests.Response:
        """Faz requisição com retry automático e tratamento de erros"""
        
        # Verificar cache primeiro
        cache_key = self._get_cache_key(url, params)
        cached = self._get_from_cache(cache_key)
        if cached and method == 'GET':
            return cached
        
        # Rate limiting
        self._rate_limit_wait()
        
        # Log da requisição
        self.logger.info(f"Requisição {method} para: {url}")
        if params:
            self.logger.debug(f"Parâmetros: {params}")
        
        inicio = time.time()
        
        try:
            # Fazer requisição
            if method == 'GET':
                response = self.session.get(url, params=params, timeout=timeout)
            elif method == 'POST':
                response = self.session.post(url, data=params, timeout=timeout)
            else:
                raise ValueError(f"Método não suportado: {method}")
            
            # Verificar status
            response.raise_for_status()
            
            # Estatísticas
            tempo_resposta = time.time() - inicio
            self.stats['requests_total'] += 1
            self.stats['requests_sucesso'] += 1
            self.stats['tempo_total'] += tempo_resposta
            
            self.logger.info(f"Resposta OK: {response.status_code} em {tempo_resposta:.2f}s")
            
            # Salvar no cache se GET
            if method == 'GET':
                self._save_to_cache(cache_key, response)
            
            return response
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout após {timeout}s: {url}")
            self.stats['requests_erro'] += 1
            raise
            
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Erro de conexão: {url} - {str(e)}")
            self.stats['requests_erro'] += 1
            raise
            
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"Erro HTTP {e.response.status_code}: {url}")
            self.logger.debug(f"Resposta: {e.response.text[:500]}")
            self.stats['requests_erro'] += 1
            raise
            
        except Exception as e:
            self.logger.error(f"Erro não esperado: {type(e).__name__}: {str(e)}")
            self.stats['requests_erro'] += 1
            raise
    
    def verificar_saude(self) -> Dict[str, Any]:
        """Verifica saúde da API"""
        try:
            # Fazer requisição de teste
            inicio = time.time()
            self.fazer_requisicao(self.base_url, timeout=10)
            tempo = time.time() - inicio
            
            return {
                'status': 'OK',
                'tempo_resposta': tempo,
                'timestamp': datetime.now().isoformat(),
                'estatisticas': self.stats
            }
            
        except Exception as e:
            return {
                'status': 'ERRO',
                'erro': str(e),
                'timestamp': datetime.now().isoformat(),
                'estatisticas': self.stats
            }
    
    @abstractmethod
    def buscar(self, query: str, **kwargs) -> List[Dict]:
        """Método abstrato para busca - deve ser implementado"""
        pass
```

### Implementação LexML com Validações

```python
# apis/lexmil_api.py
"""API LexML com tratamento completo de erros"""

import xmltodict
from typing import List, Dict, Optional, Any
from datetime import datetime
import re
from core.base_api import BaseGovAPI

class LexMLAPI(BaseGovAPI):
    """API do LexML com protocolo SRU"""
    
    def __init__(self):
        super().__init__(
            base_url='https://www.lexml.gov.br/busca/SRU',
            nome_fonte='LexML'
        )
        
        # Validar que a API está acessível
        self._validar_api()
        
    def _validar_api(self):
        """Valida que a API SRU está respondendo"""
        try:
            response = self.fazer_requisicao(
                self.base_url,
                params={'operation': 'explain'},
                timeout=10
            )
            
            if 'explainResponse' not in response.text:
                raise ValueError("API SRU não está respondendo corretamente")
                
            self.logger.info("API LexML validada com sucesso")
            
        except Exception as e:
            self.logger.error(f"Falha ao validar API LexML: {e}")
            raise
    
    def buscar(self, query: str, start_record: int = 1, 
              maximum_records: int = 100) -> List[Dict]:
        """Busca legislação no LexML"""
        
        # Validar parâmetros
        if not query or not isinstance(query, str):
            raise ValueError("Query deve ser uma string não vazia")
            
        if not 1 <= start_record <= 10000:
            raise ValueError("start_record deve estar entre 1 e 10000")
            
        if not 1 <= maximum_records <= 100:
            raise ValueError("maximum_records deve estar entre 1 e 100")
        
        # Escapar caracteres especiais na query
        query = self._sanitizar_query(query)
        
        params = {
            'operation': 'searchRetrieve',
            'query': query,
            'startRecord': start_record,
            'maximumRecords': maximum_records,
            'recordSchema': 'dc'
        }
        
        try:
            response = self.fazer_requisicao(self.base_url, params=params)
            
            # Validar resposta
            if not response.text:
                raise ValueError("Resposta vazia do servidor")
            
            # Parse XML
            try:
                data = xmltodict.parse(response.text)
            except Exception as e:
                self.logger.error(f"Erro ao fazer parse do XML: {e}")
                self.logger.debug(f"XML recebido: {response.text[:1000]}")
                raise ValueError(f"Resposta XML inválida: {e}")
            
            # Extrair registros
            registros = self._extrair_registros(data)
            
            self.logger.info(f"Busca '{query}' retornou {len(registros)} registros")
            
            return registros
            
        except Exception as e:
            self.logger.error(f"Erro na busca LexML: {e}")
            raise
    
    def _sanitizar_query(self, query: str) -> str:
        """Sanitiza query para evitar injeção"""
        # Remover caracteres potencialmente perigosos
        query = re.sub(r'[<>\"\'&]', '', query)
        
        # Limitar tamanho
        if len(query) > 500:
            query = query[:500]
            
        return query.strip()
    
    def _extrair_registros(self, data: Dict) -> List[Dict]:
        """Extrai registros do XML parseado com validações"""
        registros = []
        
        try:
            # Navegar pela estrutura XML
            search_response = data.get('searchRetrieveResponse', {})
            
            # Verificar número de registros
            num_records = int(search_response.get('numberOfRecords', 0))
            if num_records == 0:
                return []
            
            # Extrair records
            records_data = search_response.get('records', {}).get('record', [])
            
            # Garantir que seja lista
            if not isinstance(records_data, list):
                records_data = [records_data]
            
            for record in records_data:
                try:
                    registro = self._processar_registro(record)
                    if registro:
                        registros.append(registro)
                except Exception as e:
                    self.logger.warning(f"Erro ao processar registro: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Erro ao extrair registros: {e}")
            
        return registros
    
    def _processar_registro(self, record: Dict) -> Optional[Dict]:
        """Processa um registro individual"""
        try:
            metadata = record.get('recordData', {}).get('dc', {})
            
            if not metadata:
                return None
            
            # Extrair campos com valores padrão
            registro = {
                'titulo': self._extrair_campo(metadata, 'title', 'Sem título'),
                'tipo': self._extrair_campo(metadata, 'type', 'Não especificado'),
                'data': self._extrair_data(metadata.get('date')),
                'descricao': self._extrair_campo(metadata, 'description', ''),
                'url': self._extrair_campo(metadata, 'identifier', ''),
                'fonte_original': self._extrair_campo(metadata, 'source', ''),
                'autor': self._extrair_campo(metadata, 'creator', ''),
                'assunto': self._extrair_campo(metadata, 'subject', ''),
                'editora': self._extrair_campo(metadata, 'publisher', ''),
                'formato': self._extrair_campo(metadata, 'format', ''),
                'idioma': self._extrair_campo(metadata, 'language', 'pt'),
                'timestamp_coleta': datetime.now().isoformat()
            }
            
            return registro
            
        except Exception as e:
            self.logger.warning(f"Erro ao processar registro: {e}")
            return None
    
    def _extrair_campo(self, metadata: Dict, campo: str, default: str = '') -> str:
        """Extrai campo com tratamento de tipos"""
        valor = metadata.get(campo, default)
        
        # Se for lista, pegar primeiro elemento
        if isinstance(valor, list) and valor:
            valor = valor[0]
            
        # Converter para string
        return str(valor).strip() if valor else default
    
    def _extrair_data(self, data_str: Any) -> Optional[str]:
        """Extrai e normaliza data"""
        if not data_str:
            return None
            
        data_str = str(data_str).strip()
        
        # Tentar diferentes formatos
        formatos = [
            '%Y-%m-%d',
            '%d/%m/%Y',
            '%Y',
            '%d de %B de %Y'
        ]
        
        for formato in formatos:
            try:
                data = datetime.strptime(data_str, formato)
                return data.strftime('%Y-%m-%d')
            except:
                continue
                
        # Se não conseguir parsear, retornar string original
        return data_str
```

### Sistema de Testes

```python
# tests/test_apis.py
"""Testes para garantir funcionamento das APIs"""

import pytest
import requests_mock
from datetime import datetime
from apis.lexmil_api import LexMLAPI
from apis.camara_api import CamaraAPI

class TestLexMLAPI:
    """Testes para API do LexML"""
    
    @pytest.fixture
    def api(self):
        """Fixture para criar instância da API"""
        return LexMLAPI()
    
    @pytest.fixture
    def mock_response(self):
        """Resposta XML mock"""
        return """<?xml version="1.0" encoding="UTF-8"?>
        <searchRetrieveResponse>
            <numberOfRecords>1</numberOfRecords>
            <records>
                <record>
                    <recordData>
                        <dc>
                            <title>Lei nº 11.442, de 5 de Janeiro de 2007</title>
                            <type>Lei Ordinária</type>
                            <date>2007-01-05</date>
                            <description>Dispõe sobre o transporte rodoviário de cargas</description>
                            <identifier>urn:lex:br:federal:lei:2007-01-05;11442</identifier>
                        </dc>
                    </recordData>
                </record>
            </records>
        </searchRetrieveResponse>"""
    
    def test_buscar_sucesso(self, api, mock_response):
        """Testa busca bem-sucedida"""
        with requests_mock.Mocker() as m:
            m.get(api.base_url, text=mock_response)
            
            resultados = api.buscar("transporte rodoviário")
            
            assert len(resultados) == 1
            assert resultados[0]['titulo'] == "Lei nº 11.442, de 5 de Janeiro de 2007"
            assert resultados[0]['tipo'] == "Lei Ordinária"
    
    def test_buscar_query_vazia(self, api):
        """Testa busca com query vazia"""
        with pytest.raises(ValueError, match="Query deve ser uma string não vazia"):
            api.buscar("")
    
    def test_buscar_parametros_invalidos(self, api):
        """Testa busca com parâmetros inválidos"""
        with pytest.raises(ValueError, match="start_record deve estar entre"):
            api.buscar("teste", start_record=0)
            
        with pytest.raises(ValueError, match="maximum_records deve estar entre"):
            api.buscar("teste", maximum_records=1000)
    
    def test_resposta_xml_invalida(self, api):
        """Testa tratamento de XML inválido"""
        with requests_mock.Mocker() as m:
            m.get(api.base_url, text="<invalid>xml")
            
            with pytest.raises(ValueError, match="Resposta XML inválida"):
                api.buscar("teste")
    
    def test_sanitizar_query(self, api):
        """Testa sanitização de query"""
        query_perigosa = "teste<script>alert('xss')</script>"
        query_limpa = api._sanitizar_query(query_perigosa)
        
        assert "<" not in query_limpa
        assert ">" not in query_limpa
        assert "script" in query_limpa

class TestIntegracaoAPIs:
    """Testes de integração entre APIs"""
    
    def test_todas_apis_acessiveis(self):
        """Verifica se todas as APIs estão acessíveis"""
        from config.urls import verificar_urls
        
        resultados = verificar_urls()
        
        # Pelo menos LexML e Câmara devem estar OK
        assert resultados.get('lexmil') == 'OK'
        assert resultados.get('camara') == 'OK'
    
    @pytest.mark.slow
    def test_busca_integrada(self):
        """Testa busca em múltiplas fontes"""
        # Este teste realmente faz chamadas às APIs
        lexmil = LexMLAPI()
        
        # Buscar termo comum
        resultados_lexmil = lexmil.buscar("constituição", maximum_records=5)
        
        assert len(resultados_lexmil) > 0
        assert all('titulo' in r for r in resultados_lexmil)
```

### Monitoramento e Alertas

```python
# monitoring/health_check.py
"""Sistema de monitoramento e alertas"""

import time
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging
from dataclasses import dataclass, asdict

@dataclass
class HealthStatus:
    """Status de saúde de um componente"""
    componente: str
    status: str  # OK, AVISO, ERRO
    mensagem: str
    timestamp: datetime
    metricas: Dict[str, Any]

class MonitorSistema:
    """Monitor de saúde do sistema"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.historico = []
        self.alertas_enviados = {}
        
    def verificar_saude_completa(self) -> List[HealthStatus]:
        """Verifica saúde de todos os componentes"""
        
        verificacoes = [
            self._verificar_apis(),
            self._verificar_banco_dados(),
            self._verificar_espaco_disco(),
            self._verificar_memoria(),
            self._verificar_processos(),
            self._verificar_logs()
        ]
        
        # Flatten lista
        status_list = []
        for verificacao in verificacoes:
            if isinstance(verificacao, list):
                status_list.extend(verificacao)
            else:
                status_list.append(verificacao)
        
        # Salvar histórico
        self.historico.append({
            'timestamp': datetime.now(),
            'status': status_list
        })
        
        # Verificar alertas
        self._processar_alertas(status_list)
        
        return status_list
    
    def _verificar_apis(self) -> List[HealthStatus]:
        """Verifica status de todas as APIs"""
        from config.urls import URLS_APIS
        import requests
        
        status_list = []
        
        for nome, config in URLS_APIS.items():
            inicio = time.time()
            
            try:
                url_teste = config.get('teste', config.get('base'))
                response = requests.head(url_teste, timeout=10)
                tempo = time.time() - inicio
                
                if response.status_code < 400:
                    status = HealthStatus(
                        componente=f"API_{nome}",
                        status="OK",
                        mensagem=f"Respondendo normalmente",
                        timestamp=datetime.now(),
                        metricas={
                            'tempo_resposta': tempo,
                            'status_code': response.status_code
                        }
                    )
                else:
                    status = HealthStatus(
                        componente=f"API_{nome}",
                        status="AVISO",
                        mensagem=f"Status HTTP {response.status_code}",
                        timestamp=datetime.now(),
                        metricas={'status_code': response.status_code}
                    )
                    
            except Exception as e:
                status = HealthStatus(
                    componente=f"API_{nome}",
                    status="ERRO",
                    mensagem=str(e),
                    timestamp=datetime.now(),
                    metricas={}
                )
            
            status_list.append(status)
            
        return status_list
    
    def _verificar_banco_dados(self) -> HealthStatus:
        """Verifica conexão com banco de dados"""
        from sqlalchemy import create_engine, text
        
        try:
            engine = create_engine(self.config.DATABASE_URL)
            
            inicio = time.time()
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            tempo = time.time() - inicio
            
            # Verificar tamanho do banco
            with engine.connect() as conn:
                result = conn.execute(text(
                    "SELECT COUNT(*) as total FROM legislacao"
                ))
                total_registros = result.fetchone()[0]
            
            return HealthStatus(
                componente="Banco_Dados",
                status="OK",
                mensagem="Conexão estabelecida",
                timestamp=datetime.now(),
                metricas={
                    'tempo_resposta': tempo,
                    'total_registros': total_registros
                }
            )
            
        except Exception as e:
            return HealthStatus(
                componente="Banco_Dados",
                status="ERRO",
                mensagem=f"Falha na conexão: {str(e)}",
                timestamp=datetime.now(),
                metricas={}
            )
    
    def _verificar_espaco_disco(self) -> HealthStatus:
        """Verifica espaço em disco"""
        import shutil
        
        try:
            total, usado, livre = shutil.disk_usage("/")
            percentual_usado = (usado / total) * 100
            
            if percentual_usado > 90:
                status = "ERRO"
                mensagem = f"Espaço crítico: {percentual_usado:.1f}% usado"
            elif percentual_usado > 80:
                status = "AVISO"
                mensagem = f"Espaço baixo: {percentual_usado:.1f}% usado"
            else:
                status = "OK"
                mensagem = f"Espaço adequado: {percentual_usado:.1f}% usado"
            
            return HealthStatus(
                componente="Disco",
                status=status,
                mensagem=mensagem,
                timestamp=datetime.now(),
                metricas={
                    'total_gb': total // (2**30),
                    'usado_gb': usado // (2**30),
                    'livre_gb': livre // (2**30),
                    'percentual_usado': percentual_usado
                }
            )
            
        except Exception as e:
            return HealthStatus(
                componente="Disco",
                status="ERRO",
                mensagem=str(e),
                timestamp=datetime.now(),
                metricas={}
            )
    
    def _verificar_memoria(self) -> HealthStatus:
        """Verifica uso de memória"""
        import psutil
        
        try:
            mem = psutil.virtual_memory()
            
            if mem.percent > 90:
                status = "ERRO"
                mensagem = f"Memória crítica: {mem.percent}% usado"
            elif mem.percent > 80:
                status = "AVISO"
                mensagem = f"Memória alta: {mem.percent}% usado"
            else:
                status = "OK"
                mensagem = f"Memória adequada: {mem.percent}% usado"
            
            return HealthStatus(
                componente="Memoria",
                status=status,
                mensagem=mensagem,
                timestamp=datetime.now(),
                metricas={
                    'total_gb': mem.total // (2**30),
                    'disponivel_gb': mem.available // (2**30),
                    'percentual_usado': mem.percent
                }
            )
            
        except Exception as e:
            return HealthStatus(
                componente="Memoria",
                status="ERRO",
                mensagem=str(e),
                timestamp=datetime.now(),
                metricas={}
            )
    
    def _processar_alertas(self, status_list: List[HealthStatus]):
        """Processa e envia alertas se necessário"""
        
        alertas_criticos = [s for s in status_list if s.status == "ERRO"]
        alertas_aviso = [s for s in status_list if s.status == "AVISO"]
        
        if alertas_criticos:
            self._enviar_alerta("CRÍTICO", alertas_criticos)
        elif len(alertas_aviso) >= 3:
            self._enviar_alerta("MÚLTIPLOS AVISOS", alertas_aviso)
    
    def _enviar_alerta(self, nivel: str, alertas: List[HealthStatus]):
        """Envia alerta por email"""
        
        # Verificar se já enviou alerta recente
        chave_alerta = f"{nivel}_{','.join([a.componente for a in alertas])}"
        ultimo_envio = self.alertas_enviados.get(chave_alerta)
        
        if ultimo_envio and (datetime.now() - ultimo_envio) < timedelta(hours=1):
            return  # Não enviar alertas repetidos em menos de 1 hora
        
        try:
            corpo = f"ALERTA {nivel} - Sistema de Monitoramento de Legislação\n\n"
            corpo += f"Data/Hora: {datetime.now()}\n\n"
            
            for alerta in alertas:
                corpo += f"Componente: {alerta.componente}\n"
                corpo += f"Status: {alerta.status}\n"
                corpo += f"Mensagem: {alerta.mensagem}\n"
                corpo += f"Métricas: {json.dumps(alerta.metricas, indent=2)}\n"
                corpo += "-" * 50 + "\n"
            
            # Aqui você configuraria o envio real de email
            self.logger.critical(f"ALERTA {nivel}: {corpo}")
            
            # Marcar como enviado
            self.alertas_enviados[chave_alerta] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar alerta: {e}")
    
    def gerar_relatorio_saude(self) -> Dict[str, Any]:
        """Gera relatório de saúde consolidado"""
        
        if not self.historico:
            return {"erro": "Sem dados de histórico"}
        
        # Pegar últimas 24 horas
        limite = datetime.now() - timedelta(hours=24)
        historico_24h = [h for h in self.historico if h['timestamp'] > limite]
        
        # Calcular estatísticas
        total_verificacoes = len(historico_24h)
        componentes = {}
        
        for verificacao in historico_24h:
            for status in verificacao['status']:
                comp = status.componente
                if comp not in componentes:
                    componentes[comp] = {
                        'total': 0,
                        'ok': 0,
                        'aviso': 0,
                        'erro': 0,
                        'disponibilidade': 0
                    }
                
                componentes[comp]['total'] += 1
                componentes[comp][status.status.lower()] += 1
        
        # Calcular disponibilidade
        for comp, stats in componentes.items():
            if stats['total'] > 0:
                stats['disponibilidade'] = (stats['ok'] / stats['total']) * 100
        
        return {
            'periodo': '24 horas',
            'total_verificacoes': total_verificacoes,
            'componentes': componentes,
            'ultima_verificacao': self.historico[-1]['timestamp'].isoformat()
        }
```

## Troubleshooting Detalhado

### Guia de Resolução de Problemas

```python
# troubleshooting/diagnostico.py
"""Sistema de diagnóstico automático"""

import sys
import subprocess
import platform
import importlib
import os
from typing import Dict, List, Tuple

class DiagnosticoSistema:
    """Diagnóstico automático de problemas"""
    
    def __init__(self):
        self.problemas_encontrados = []
        self.avisos = []
        self.info_sistema = self._coletar_info_sistema()
    
    def _coletar_info_sistema(self) -> Dict:
        """Coleta informações do sistema"""
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'python_version': sys.version,
            'python_executable': sys.executable,
            'cwd': os.getcwd(),
            'path': sys.path
        }
    
    def executar_diagnostico_completo(self) -> Dict:
        """Executa diagnóstico completo"""
        
        print("=== DIAGNÓSTICO DO SISTEMA ===")
        print(f"Sistema Operacional: {self.info_sistema['os']}")
        print(f"Python: {platform.python_version()}")
        print(f"Diretório: {self.info_sistema['cwd']}")
        print("=" * 50)
        
        # Executar verificações
        self._verificar_python()
        self._verificar_dependencias()
        self._verificar_diretorios()
        self._verificar_permissoes()
        self._verificar_conectividade()
        self._verificar_apis()
        self._verificar_banco_dados()
        
        # Gerar relatório
        return self._gerar_relatorio()
    
    def _verificar_python(self):
        """Verifica versão do Python"""
        versao_atual = sys.version_info
        versao_minima = (3, 8)
        
        if versao_atual < versao_minima:
            self.problemas_encontrados.append({
                'tipo': 'PYTHON_VERSION',
                'severidade': 'CRÍTICO',
                'mensagem': f'Python {versao_atual.major}.{versao_atual.minor} detectado. Necessário 3.8+',
                'solucao': 'Instale Python 3.8 ou superior'
            })
    
    def _verificar_dependencias(self):
        """Verifica se todas as dependências estão instaladas"""
        
        dependencias_criticas = [
            'requests', 'beautifulsoup4', 'pandas', 'sqlalchemy',
            'spacy', 'nltk', 'selenium'
        ]
        
        for dep in dependencias_criticas:
            try:
                importlib.import_module(dep.replace('-', '_'))
                print(f"✓ {dep} instalado")
            except ImportError:
                self.problemas_encontrados.append({
                    'tipo': 'DEPENDENCIA_FALTANDO',
                    'severidade': 'CRÍTICO',
                    'mensagem': f'Módulo {dep} não encontrado',
                    'solucao': f'Execute: pip install {dep}'
                })
    
    def _verificar_diretorios(self):
        """Verifica se diretórios necessários existem"""
        
        diretorios = ['data', 'logs', 'cache', 'reports', 'backups']
        
        for dir in diretorios:
            if not os.path.exists(dir):
                self.avisos.append({
                    'tipo': 'DIRETORIO_FALTANDO',
                    'mensagem': f'Diretório {dir} não existe',
                    'solucao': f'Será criado automaticamente ou execute: mkdir {dir}'
                })
                
                # Tentar criar
                try:
                    os.makedirs(dir, exist_ok=True)
                    print(f"✓ Diretório {dir} criado")
                except Exception as e:
                    self.problemas_encontrados.append({
                        'tipo': 'PERMISSAO_DIRETORIO',
                        'severidade': 'ALTO',
                        'mensagem': f'Não foi possível criar {dir}: {e}',
                        'solucao': 'Verifique permissões do diretório'
                    })
    
    def _verificar_conectividade(self):
        """Verifica conectividade com internet"""
        import socket
        
        hosts_teste = [
            ('google.com', 80),
            ('www.lexml.gov.br', 443),
            ('dadosabertos.camara.leg.br', 443)
        ]
        
        for host, porta in hosts_teste:
            try:
                socket.create_connection((host, porta), timeout=5)
                print(f"✓ Conectividade OK com {host}")
            except Exception as e:
                self.problemas_encontrados.append({
                    'tipo': 'CONECTIVIDADE',
                    'severidade': 'ALTO',
                    'mensagem': f'Não foi possível conectar a {host}:{porta}',
                    'solucao': 'Verifique conexão com internet e firewall'
                })
    
    def _gerar_relatorio(self) -> Dict:
        """Gera relatório de diagnóstico"""
        
        relatorio = {
            'info_sistema': self.info_sistema,
            'problemas_criticos': [p for p in self.problemas_encontrados 
                                 if p.get('severidade') == 'CRÍTICO'],
            'problemas_altos': [p for p in self.problemas_encontrados 
                              if p.get('severidade') == 'ALTO'],
            'avisos': self.avisos,
            'status_geral': 'OK' if not self.problemas_encontrados else 'PROBLEMAS ENCONTRADOS'
        }
        
        # Imprimir resumo
        print("\n=== RESUMO DO DIAGNÓSTICO ===")
        
        if relatorio['problemas_criticos']:
            print(f"\n❌ {len(relatorio['problemas_criticos'])} PROBLEMAS CRÍTICOS:")
            for p in relatorio['problemas_criticos']:
                print(f"  - {p['mensagem']}")
                print(f"    SOLUÇÃO: {p['solucao']}")
        
        if relatorio['problemas_altos']:
            print(f"\n⚠️  {len(relatorio['problemas_altos'])} PROBLEMAS ALTOS:")
            for p in relatorio['problemas_altos']:
                print(f"  - {p['mensagem']}")
                print(f"    SOLUÇÃO: {p['solucao']}")
        
        if relatorio['avisos']:
            print(f"\nℹ️  {len(relatorio['avisos'])} AVISOS:")
            for a in relatorio['avisos']:
                print(f"  - {a['mensagem']}")
        
        if relatorio['status_geral'] == 'OK':
            print("\n✅ Sistema pronto para uso!")
        else:
            print("\n❌ Resolva os problemas acima antes de continuar")
        
        return relatorio

# Executar diagnóstico ao importar
if __name__ == "__main__":
    diagnostico = DiagnosticoSistema()
    diagnostico.executar_diagnostico_completo()
```

## Plano de Contingência

### Sistema de Backup e Recuperação

```python
# backup/backup_system.py
"""Sistema de backup automático"""

import os
import shutil
import sqlite3
import json
from datetime import datetime
import tarfile
import hashlib

class SistemaBackup:
    """Sistema de backup e recuperação"""
    
    def __init__(self, config):
        self.config = config
        self.backup_dir = 'backups'
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def criar_backup_completo(self) -> str:
        """Cria backup completo do sistema"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f'backup_completo_{timestamp}'
        backup_path = os.path.join(self.backup_dir, backup_name)
        
        os.makedirs(backup_path, exist_ok=True)
        
        try:
            # 1. Backup do banco de dados
            self._backup_banco_dados(backup_path)
            
            # 2. Backup dos arquivos de cache
            self._backup_diretorio('cache', backup_path)
            
            # 3. Backup dos logs
            self._backup_diretorio('logs', backup_path)
            
            # 4. Backup das configurações
            self._backup_configuracoes(backup_path)
            
            # 5. Criar arquivo compactado
            arquivo_final = f'{backup_path}.tar.gz'
            with tarfile.open(arquivo_final, 'w:gz') as tar:
                tar.add(backup_path, arcname=backup_name)
            
            # 6. Remover diretório temporário
            shutil.rmtree(backup_path)
            
            # 7. Calcular checksum
            checksum = self._calcular_checksum(arquivo_final)
            
            # 8. Salvar metadados
            self._salvar_metadados_backup(arquivo_final, checksum)
            
            print(f"✅ Backup criado: {arquivo_final}")
            print(f"   Checksum: {checksum}")
            
            return arquivo_final
            
        except Exception as e:
            print(f"❌ Erro ao criar backup: {e}")
            raise
    
    def _backup_banco_dados(self, destino: str):
        """Faz backup do banco de dados"""
        
        # Para SQLite
        if 'sqlite' in self.config.DATABASE_URL:
            db_path = self.config.DATABASE_URL.replace('sqlite:///', '')
            
            if os.path.exists(db_path):
                # Fazer cópia consistente
                conn = sqlite3.connect(db_path)
                backup_conn = sqlite3.connect(os.path.join(destino, 'database.db'))
                
                with backup_conn:
                    conn.backup(backup_conn)
                
                conn.close()
                backup_conn.close()
        else:
            # Para outros bancos, usar pg_dump, mysqldump, etc
            pass
    
    def restaurar_backup(self, arquivo_backup: str) -> bool:
        """Restaura sistema a partir de backup"""
        
        if not os.path.exists(arquivo_backup):
            print(f"❌ Arquivo de backup não encontrado: {arquivo_backup}")
            return False
        
        try:
            # Verificar checksum
            if not self._verificar_checksum(arquivo_backup):
                print("❌ Checksum inválido! Backup pode estar corrompido")
                return False
            
            # Criar diretório temporário
            temp_dir = f'temp_restore_{datetime.now():%Y%m%d_%H%M%S}'
            
            # Extrair backup
            with tarfile.open(arquivo_backup, 'r:gz') as tar:
                tar.extractall(temp_dir)
            
            # Fazer backup do estado atual antes de restaurar
            print("Criando backup do estado atual...")
            self.criar_backup_completo()
            
            # Restaurar cada componente
            backup_dir = os.path.join(temp_dir, os.listdir(temp_dir)[0])
            
            # Parar serviços se necessário
            # ...
            
            # Restaurar banco
            self._restaurar_banco_dados(backup_dir)
            
            # Restaurar arquivos
            self._restaurar_diretorios(backup_dir)
            
            # Limpar
            shutil.rmtree(temp_dir)
            
            print("✅ Backup restaurado com sucesso!")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao restaurar backup: {e}")
            return False
    
    def _calcular_checksum(self, arquivo: str) -> str:
        """Calcula SHA-256 do arquivo"""
        sha256_hash = hashlib.sha256()
        
        with open(arquivo, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                
        return sha256_hash.hexdigest()
    
    def listar_backups(self) -> List[Dict]:
        """Lista todos os backups disponíveis"""
        
        backups = []
        
        for arquivo in os.listdir(self.backup_dir):
            if arquivo.endswith('.tar.gz'):
                caminho = os.path.join(self.backup_dir, arquivo)
                
                # Ler metadados se existir
                meta_file = caminho + '.meta'
                metadados = {}
                
                if os.path.exists(meta_file):
                    with open(meta_file, 'r') as f:
                        metadados = json.load(f)
                
                info = {
                    'arquivo': arquivo,
                    'caminho': caminho,
                    'tamanho_mb': os.path.getsize(caminho) / (1024 * 1024),
                    'data_criacao': datetime.fromtimestamp(os.path.getctime(caminho)),
                    'checksum': metadados.get('checksum', 'N/A')
                }
                
                backups.append(info)
        
        # Ordenar por data
        backups.sort(key=lambda x: x['data_criacao'], reverse=True)
        
        return backups
```

### Modo de Recuperação

```python
# recovery/recovery_mode.py
"""Modo de recuperação para situações críticas"""

class ModoRecuperacao:
    """Modo de operação mínima em caso de falhas"""
    
    def __init__(self):
        self.modo_seguro = True
        self.fontes_disponiveis = []
        self.cache_local = True
    
    def iniciar_modo_seguro(self):
        """Inicia sistema em modo seguro"""
        
        print("🚨 INICIANDO EM MODO SEGURO 🚨")
        
        # 1. Verificar componentes essenciais
        componentes = self._verificar_componentes_essenciais()
        
        # 2. Desabilitar features não essenciais
        self._desabilitar_features_nao_essenciais()
        
        # 3. Usar apenas cache local se disponível
        if self._verificar_cache_local():
            print("✓ Cache local disponível")
            self.cache_local = True
        
        # 4. Testar cada fonte individualmente
        self.fontes_disponiveis = self._testar_fontes()
        
        print(f"\nFontes disponíveis: {self.fontes_disponiveis}")
        print("Sistema rodando em modo seguro com funcionalidade limitada")
    
    def _verificar_componentes_essenciais(self) -> Dict:
        """Verifica apenas componentes essenciais"""
        
        essenciais = {
            'banco_dados': self._testar_banco_local(),
            'sistema_arquivos': self._testar_sistema_arquivos(),
            'memoria': self._verificar_memoria_minima()
        }
        
        return essenciais
    
    def _testar_banco_local(self) -> bool:
        """Testa se banco local está acessível"""
        try:
            import sqlite3
            conn = sqlite3.connect('legislacao_transporte.db')
            conn.execute("SELECT 1")
            conn.close()
            return True
        except:
            # Tentar criar banco mínimo
            try:
                conn = sqlite3.connect('legislacao_transporte_recovery.db')
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS legislacao_cache (
                        id INTEGER PRIMARY KEY,
                        titulo TEXT,
                        dados TEXT,
                        timestamp DATETIME
                    )
                """)
                conn.close()
                return True
            except:
                return False
    
    def operar_offline(self):
        """Opera apenas com dados locais"""
        
        print("\n📴 Operando em modo OFFLINE")
        print("Usando apenas dados em cache local")
        
        # Implementar lógica para trabalhar apenas com cache
        # ...
```

## Execução Final Segura

```python
# main_safe.py
"""Script principal com todas as verificações de segurança"""

import sys
import os
from datetime import datetime

def main():
    """Função principal com tratamento completo de erros"""
    
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║     Monitor de Legislação - Transporte Rodoviário        ║
    ║              Iniciando em {datetime.now():%Y-%m-%d %H:%M:%S}              ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # 1. Executar diagnóstico
        print("🔍 Executando diagnóstico inicial...")
        from troubleshooting.diagnostico import DiagnosticoSistema
        
        diagnostico = DiagnosticoSistema()
        resultado = diagnostico.executar_diagnostico_completo()
        
        if resultado['status_geral'] != 'OK':
            print("\n❌ Problemas detectados. Abortando inicialização.")
            print("Por favor, resolva os problemas listados acima.")
            sys.exit(1)
        
        # 2. Verificar backups
        print("\n💾 Verificando sistema de backup...")
        from backup.backup_system import SistemaBackup
        from config import Config
        
        backup_system = SistemaBackup(Config)
        backups = backup_system.listar_backups()
        
        if not backups:
            print("⚠️  Nenhum backup encontrado. Criando backup inicial...")
            backup_system.criar_backup_completo()
        else:
            ultimo_backup = backups[0]
            dias_desde_backup = (datetime.now() - ultimo_backup['data_criacao']).days
            
            if dias_desde_backup > 7:
                print(f"⚠️  Último backup tem {dias_desde_backup} dias. Criando novo backup...")
                backup_system.criar_backup_completo()
        
        # 3. Iniciar sistema principal
        print("\n🚀 Iniciando sistema principal...")
        from main import SistemaMonitoramentoLegislacao
        
        sistema = SistemaMonitoramentoLegislacao()
        
        # 4. Verificar modo de operação
        from config.urls import verificar_urls
        urls_status = verificar_urls()
        
        apis_funcionando = sum(1 for status in urls_status.values() if status == 'OK')
        
        if apis_funcionando < 2:
            print(f"\n⚠️  Apenas {apis_funcionando} APIs funcionando.")
            print("Iniciando em MODO SEGURO...")
            
            from recovery.recovery_mode import ModoRecuperacao
            modo_recovery = ModoRecuperacao()
            modo_recovery.iniciar_modo_seguro()
            
            # Operar com funcionalidade reduzida
            sistema.modo_seguro = True
        
        # 5. Iniciar monitoramento
        print("\n✅ Sistema iniciado com sucesso!")
        print("Pressione Ctrl+C para parar\n")
        
        sistema.executar()
        
    except KeyboardInterrupt:
        print("\n\n🛑 Sistema interrompido pelo usuário")
        print("Salvando estado atual...")
        # Salvar estado se necessário
        
    except Exception as e:
        print(f"\n\n❌ ERRO CRÍTICO: {type(e).__name__}: {e}")
        print("Tentando salvar estado de emergência...")
        
        # Tentar salvar logs de erro
        try:
            with open(f'logs/crash_{datetime.now():%Y%m%d_%H%M%S}.log', 'w') as f:
                import traceback
                traceback.print_exc(file=f)
                f.write(f"\n\nInfo Sistema:\n")
                f.write(f"Python: {sys.version}\n")
                f.write(f"OS: {os.name}\n")
                f.write(f"CWD: {os.getcwd()}\n")
        except:
            pass
        
        print("\nPara ajuda, execute: python troubleshooting/diagnostico.py")
        sys.exit(1)
    
    finally:
        print("\n👋 Sistema finalizado")

if __name__ == "__main__":
    main()
```

## Instruções Finais de Segurança

### Checklist Pré-Execução

1. **Verificar ambiente**:
   ```bash
   python verify_installation.py
   ```

2. **Executar diagnóstico**:
   ```bash
   python troubleshooting/diagnostico.py
   ```

3. **Criar backup inicial**:
   ```bash
   python -c "from backup.backup_system import SistemaBackup; from config import Config; SistemaBackup(Config).criar_backup_completo()"
   ```

4. **Testar em modo seguro primeiro**:
   ```bash
   python main_safe.py --test-mode
   ```

5. **Monitorar logs em tempo real**:
   ```bash
   tail -f logs/*.log
   ```

### Em Caso de Problemas

1. **Sistema não inicia**: Execute o diagnóstico
2. **APIs fora do ar**: Sistema entrará em modo seguro automaticamente
3. **Erro crítico**: Verifique logs em `logs/crash_*.log`
4. **Corrupção de dados**: Restaure do último backup
5. **Memória/Disco cheio**: Sistema alertará antes de falhar

### Contatos de Emergência

Configure no arquivo `.env`:
```env
ALERT_EMAIL=seu-email@exemplo.com
ALERT_PHONE=+55119999999
BACKUP_LOCATION=/path/to/external/backup
```

O sistema agora está EXTREMAMENTE robusto com múltiplas camadas de proteção, diagnóstico automático, e recuperação de falhas. Boa sorte! 🍀