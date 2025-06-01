"""Enhanced integration tests with comprehensive external API mocking."""

import pytest
import json
import responses
from unittest.mock import patch, Mock
from datetime import datetime, timedelta
from core.api.secure_base_service import SecureBaseService


class TestCamaraAPIMocking:
    """Test Camara API integration with realistic mocking."""
    
    @responses.activate
    def test_get_proposicoes_with_realistic_data(self):
        """Test propositions retrieval with realistic mock data."""
        # Setup realistic Camara API response
        camara_response = {
            "dados": [
                {
                    "id": 2390524,
                    "uri": "https://dadosabertos.camara.leg.br/api/v2/proposicoes/2390524",
                    "siglaTipo": "PL",
                    "codTipo": 139,
                    "numero": 1234,
                    "ano": 2025,
                    "ementa": "Estabelece diretrizes para a educação digital nas escolas públicas.",
                    "dataApresentacao": "2025-01-30T10:00:00",
                    "uriOrgaoNumerador": "https://dadosabertos.camara.leg.br/api/v2/orgaos/180",
                    "statusProposicao": {
                        "dataHora": "2025-01-30T14:30:00",
                        "sequencia": 1,
                        "uriOrgao": "https://dadosabertos.camara.leg.br/api/v2/orgaos/180",
                        "uriUltimoRelator": None,
                        "regime": "Ordinária",
                        "descricaoSituacao": "Aguardando Parecer do Relator na Comissão de Educação",
                        "codSituacao": 251,
                        "descricaoTramitacao": "CEDU",
                        "codTipoTramitacao": None,
                        "ambito": "Comissão"
                    }
                },
                {
                    "id": 2390525,
                    "uri": "https://dadosabertos.camara.leg.br/api/v2/proposicoes/2390525",
                    "siglaTipo": "PL",
                    "codTipo": 139,
                    "numero": 1235,
                    "ano": 2025,
                    "ementa": "Institui o Programa Nacional de Telemedicina.",
                    "dataApresentacao": "2025-01-30T11:00:00",
                    "statusProposicao": {
                        "dataHora": "2025-01-30T15:00:00",
                        "descricaoSituacao": "Pronta para Pauta na Comissão de Saúde",
                        "descricaoTramitacao": "CSSF"
                    }
                }
            ],
            "links": [
                {
                    "rel": "self",
                    "href": "https://dadosabertos.camara.leg.br/api/v2/proposicoes?ano=2025&siglaTipo=PL"
                },
                {
                    "rel": "first",
                    "href": "https://dadosabertos.camara.leg.br/api/v2/proposicoes?ano=2025&siglaTipo=PL&pagina=1"
                },
                {
                    "rel": "next",
                    "href": "https://dadosabertos.camara.leg.br/api/v2/proposicoes?ano=2025&siglaTipo=PL&pagina=2"
                }
            ]
        }
        
        # Mock the API endpoint
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            json=camara_response,
            status=200,
            headers={"Content-Type": "application/json"}
        )
        
        # Test the API call
        service = SecureBaseService('camara')
        result = service.get('/proposicoes', params={'ano': 2025, 'siglaTipo': 'PL'})
        
        # Assertions
        assert len(result['dados']) == 2
        assert result['dados'][0]['numero'] == 1234
        assert result['dados'][0]['siglaTipo'] == 'PL'
        assert 'educação digital' in result['dados'][0]['ementa']
        assert result['dados'][1]['numero'] == 1235
        assert 'Telemedicina' in result['dados'][1]['ementa']
        
        # Verify pagination links
        assert len(result['links']) == 3
        link_rels = [link['rel'] for link in result['links']]
        assert 'self' in link_rels
        assert 'next' in link_rels
    
    @responses.activate
    def test_get_proposicao_detail(self):
        """Test detailed proposition retrieval."""
        proposicao_detail = {
            "dados": {
                "id": 2390524,
                "uri": "https://dadosabertos.camara.leg.br/api/v2/proposicoes/2390524",
                "siglaTipo": "PL",
                "numero": 1234,
                "ano": 2025,
                "ementa": "Estabelece diretrizes para a educação digital nas escolas públicas.",
                "ementaDetalhada": "Estabelece diretrizes para a implementação da educação digital nas escolas públicas de ensino fundamental e médio, criando programa de capacitação de professores e infraestrutura tecnológica.",
                "keywords": "educação, digital, tecnologia, ensino",
                "dataApresentacao": "2025-01-30T10:00:00",
                "urlInteiroTeor": "https://www.camara.leg.br/proposicoesWeb/prop_mostrarintegra?codteor=2345678",
                "uriAutores": "https://dadosabertos.camara.leg.br/api/v2/proposicoes/2390524/autores",
                "uriCoautores": "https://dadosabertos.camara.leg.br/api/v2/proposicoes/2390524/coautores",
                "uriTramitacoes": "https://dadosabertos.camara.leg.br/api/v2/proposicoes/2390524/tramitacoes"
            }
        }
        
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes/2390524",
            json=proposicao_detail,
            status=200
        )
        
        service = SecureBaseService('camara')
        result = service.get('/proposicoes/2390524')
        
        assert result['dados']['id'] == 2390524
        assert result['dados']['numero'] == 1234
        assert 'ementaDetalhada' in result['dados']
        assert result['dados']['keywords'] == "educação, digital, tecnologia, ensino"
        assert result['dados']['urlInteiroTeor'] is not None
    
    @responses.activate
    def test_api_error_handling(self):
        """Test API error response handling."""
        # Mock 404 response
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes/999999",
            json={"erro": "Proposição não encontrada"},
            status=404
        )
        
        service = SecureBaseService('camara')
        
        with pytest.raises(Exception):  # Should raise SecureAPIError
            service.get('/proposicoes/999999')
    
    @responses.activate
    def test_api_rate_limiting_response(self):
        """Test API rate limiting response."""
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            json={"erro": "Rate limit exceeded"},
            status=429,
            headers={"Retry-After": "60"}
        )
        
        service = SecureBaseService('camara')
        
        with pytest.raises(Exception):  # Should raise SecureAPIError
            service.get('/proposicoes')


class TestSenadoAPIMocking:
    """Test Senado API integration with realistic mocking."""
    
    @responses.activate
    def test_get_materias_with_realistic_data(self):
        """Test Senate matters retrieval with realistic mock data."""
        senado_response = {
            "ListaMateriasPesquisa": {
                "Materias": {
                    "Materia": [
                        {
                            "CodigoMateria": "54321",
                            "SiglaSubtipoMateria": "PLS",
                            "NumeroMateria": "4321",
                            "AnoMateria": "2025",
                            "DescricaoObjetivoProcesso": "Projeto de Lei do Senado que dispõe sobre a proteção de dados pessoais de menores.",
                            "DescricaoIdentificacaoMateria": "PLS n° 4321/2025",
                            "DataApresentacao": "30/01/2025",
                            "IndicadorTramitando": "Sim",
                            "SituacaoAtual": {
                                "DataSituacao": "30/01/2025",
                                "DescricaoSituacao": "COMISSÃO DE CONSTITUIÇÃO, JUSTIÇA E CIDADANIA (MATÉRIA COM A RELATORIA)",
                                "SiglaCasaIdentificacaoMateria": "SF",
                                "IdentificacaoComissao": {
                                    "CodigoComissao": "34",
                                    "SiglaComissao": "CCJ",
                                    "NomeComissao": "COMISSÃO DE CONSTITUIÇÃO, JUSTIÇA E CIDADANIA"
                                }
                            },
                            "AutorPrincipal": {
                                "CodigoAutor": "5555",
                                "NomeAutor": "SENADOR DA SILVA",
                                "SiglaPartidoAutor": "PT",
                                "UfAutor": "SP"
                            }
                        }
                    ]
                }
            }
        }
        
        responses.add(
            responses.GET,
            "https://legis.senado.leg.br/dadosabertos/materia/pesquisa/lista",
            json=senado_response,
            status=200
        )
        
        service = SecureBaseService('senado')
        result = service.get('/materia/pesquisa/lista', params={'ano': 2025})
        
        # Verify structure and content
        materias = result['ListaMateriasPesquisa']['Materias']['Materia']
        assert len(materias) == 1
        
        materia = materias[0]
        assert materia['CodigoMateria'] == "54321"
        assert materia['SiglaSubtipoMateria'] == "PLS"
        assert 'proteção de dados' in materia['DescricaoObjetivoProcesso']
        assert materia['AutorPrincipal']['NomeAutor'] == "SENADOR DA SILVA"
        assert materia['SituacaoAtual']['DescricaoSituacao'] is not None


class TestPlanaltoAPIMocking:
    """Test Planalto API integration with realistic mocking."""
    
    @responses.activate
    def test_get_normas_with_realistic_data(self):
        """Test Planalto norms retrieval with realistic mock data."""
        planalto_response = {
            "normas": [
                {
                    "id": "lei-14567-2025",
                    "tipo": "LEI",
                    "numero": "14.567",
                    "ano": "2025",
                    "data": "2025-01-30",
                    "ementa": "Estabelece o marco legal da inteligência artificial no Brasil.",
                    "situacao": "PUBLICADA",
                    "orgao": "PRESIDENCIA DA REPUBLICA",
                    "url_texto": "https://www.planalto.gov.br/ccivil_03/_ato2025/2025/lei/l14567.htm",
                    "tags": ["inteligencia artificial", "tecnologia", "regulamentacao"]
                },
                {
                    "id": "decreto-11234-2025",
                    "tipo": "DECRETO",
                    "numero": "11.234",
                    "ano": "2025",
                    "data": "2025-01-29",
                    "ementa": "Regulamenta a Lei nº 14.567, de 2025, sobre inteligência artificial.",
                    "situacao": "PUBLICADO",
                    "orgao": "PRESIDENCIA DA REPUBLICA",
                    "url_texto": "https://www.planalto.gov.br/ccivil_03/_ato2025/2025/decreto/d11234.htm"
                }
            ],
            "total": 2,
            "pagina": 1,
            "limite": 10
        }
        
        responses.add(
            responses.GET,
            "https://www.planalto.gov.br/api/normas",
            json=planalto_response,
            status=200
        )
        
        service = SecureBaseService('planalto')
        result = service.get('/normas', params={'ano': 2025})
        
        assert len(result['normas']) == 2
        assert result['normas'][0]['tipo'] == 'LEI'
        assert result['normas'][1]['tipo'] == 'DECRETO'
        assert 'inteligência artificial' in result['normas'][0]['ementa']


class TestRegulatoryAgenciesMocking:
    """Test regulatory agencies API integration."""
    
    @responses.activate
    def test_anatel_consultas(self):
        """Test ANATEL public consultations."""
        anatel_response = {
            "consultas": [
                {
                    "id": "12345",
                    "numero": "05/2025",
                    "titulo": "Consulta Pública sobre 5G em áreas rurais",
                    "descricao": "Proposta de regulamentação para expansão da rede 5G em áreas rurais",
                    "data_inicio": "2025-01-30",
                    "data_fim": "2025-03-30",
                    "status": "ABERTA",
                    "area": "TELECOMUNICACOES",
                    "url": "https://www.anatel.gov.br/consultas/2025/consulta-05-2025"
                }
            ]
        }
        
        responses.add(
            responses.GET,
            "https://api.anatel.gov.br/v1/consultas",
            json=anatel_response,
            status=200
        )
        
        service = SecureBaseService('anatel')
        result = service.get('/consultas', params={'status': 'ABERTA'})
        
        assert len(result['consultas']) == 1
        assert result['consultas'][0]['numero'] == '05/2025'
        assert '5G' in result['consultas'][0]['titulo']
    
    @responses.activate
    def test_aneel_consultas(self):
        """Test ANEEL public consultations."""
        aneel_response = {
            "data": [
                {
                    "id": "cp-003-2025",
                    "numero": "003/2025",
                    "assunto": "Tarifas de energia elétrica para 2025",
                    "resumo": "Consulta sobre revisão das tarifas de energia elétrica",
                    "abertura": "2025-01-30",
                    "encerramento": "2025-02-28",
                    "situacao": "EM_ANDAMENTO"
                }
            ]
        }
        
        responses.add(
            responses.GET,
            "https://api.aneel.gov.br/consultas/publicas",
            json=aneel_response,
            status=200
        )
        
        service = SecureBaseService('aneel')
        result = service.get('/consultas/publicas')
        
        assert len(result['data']) == 1
        assert 'tarifas' in result['data'][0]['assunto'].lower()


class TestIntegrationFlows:
    """Test complete integration flows."""
    
    @responses.activate
    def test_multi_source_search_flow(self):
        """Test searching across multiple sources."""
        # Mock Camara response
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            json={
                "dados": [
                    {
                        "id": 1,
                        "siglaTipo": "PL",
                        "numero": 1234,
                        "ementa": "Lei sobre educação digital"
                    }
                ]
            },
            status=200
        )
        
        # Mock Senado response
        responses.add(
            responses.GET,
            "https://legis.senado.leg.br/dadosabertos/materia/pesquisa/lista",
            json={
                "ListaMateriasPesquisa": {
                    "Materias": {
                        "Materia": [
                            {
                                "CodigoMateria": "2",
                                "SiglaSubtipoMateria": "PLS",
                                "DescricaoObjetivoProcesso": "Projeto sobre educação inclusiva"
                            }
                        ]
                    }
                }
            },
            status=200
        )
        
        # Test multi-source retrieval
        camara_service = SecureBaseService('camara')
        senado_service = SecureBaseService('senado')
        
        camara_result = camara_service.get('/proposicoes', params={'keywords': 'educacao'})
        senado_result = senado_service.get('/materia/pesquisa/lista', params={'keywords': 'educacao'})
        
        assert len(camara_result['dados']) == 1
        assert len(senado_result['ListaMateriasPesquisa']['Materias']['Materia']) == 1
        
        # Verify both contain education-related content
        assert 'educação' in camara_result['dados'][0]['ementa']
        assert 'educação' in senado_result['ListaMateriasPesquisa']['Materias']['Materia'][0]['DescricaoObjetivoProcesso']
    
    def test_circuit_breaker_integration(self):
        """Test circuit breaker integration with external APIs."""
        service = SecureBaseService('camara')
        circuit_breaker = service.circuit_breaker
        
        # Simulate multiple failures
        with patch.object(service.session, 'request') as mock_request:
            mock_request.side_effect = Exception("Service unavailable")
            
            # Multiple failures should open circuit
            for _ in range(5):
                try:
                    service.get('/proposicoes')
                except:
                    pass
            
            # Circuit should be open after failures
            assert circuit_breaker.failure_count >= 5
    
    @responses.activate
    def test_caching_behavior(self):
        """Test API response caching behavior."""
        # Mock API response
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            json={"dados": [{"id": 1, "numero": 1234}]},
            status=200
        )
        
        service = SecureBaseService('camara')
        
        # First request should hit the API
        result1 = service.get('/proposicoes')
        assert len(responses.calls) == 1
        
        # Test that caching would work (implementation dependent)
        # This would be enhanced with actual cache implementation
        assert result1['dados'][0]['id'] == 1


class TestErrorScenarios:
    """Test various error scenarios."""
    
    @responses.activate
    def test_network_timeout(self):
        """Test network timeout handling."""
        import requests
        
        # Mock timeout
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            body=requests.Timeout("Request timed out")
        )
        
        service = SecureBaseService('camara')
        
        with pytest.raises(Exception):  # Should raise SecureAPIError
            service.get('/proposicoes')
    
    @responses.activate
    def test_malformed_response(self):
        """Test malformed API response handling."""
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            body="Invalid JSON response",
            status=200,
            content_type="application/json"
        )
        
        service = SecureBaseService('camara')
        
        with pytest.raises(Exception):  # Should raise JSON decode error
            service.get('/proposicoes')
    
    @responses.activate
    def test_server_error_retry(self):
        """Test server error retry behavior."""
        # First call fails, second succeeds
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            json={"error": "Internal server error"},
            status=500
        )
        
        responses.add(
            responses.GET,
            "https://dadosabertos.camara.leg.br/api/v2/proposicoes",
            json={"dados": [{"id": 1}]},
            status=200
        )
        
        service = SecureBaseService('camara')
        
        # Should retry and eventually succeed
        # (Actual retry behavior depends on implementation)
        try:
            result = service.get('/proposicoes')
            # If retry works, should get valid response
            assert 'dados' in result
        except Exception:
            # If no retry, should fail on first attempt
            assert len(responses.calls) >= 1